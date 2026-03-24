// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Cryptographic utilities for the Ika OWS provider:
 * - Mnemonic encryption/decryption (AES-256-GCM + scrypt)
 * - Private key derivation from mnemonic
 * - Hex encoding utilities
 */

import { Curve } from '@ika.xyz/sdk';
import { gcm } from '@noble/ciphers/aes';
import { scrypt } from '@noble/hashes/scrypt.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { HDKey } from '@scure/bip32';
import { generateMnemonic as bip39Generate, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import { OWSError, OWSErrorCode } from '../errors.js';
import { derivePath } from './ed25519-hd-key.js';

// ─── Scrypt Parameters ───────────────────────────────────────────────────
const SCRYPT_N = 2 ** 18;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DKLEN = 32;
const SALT_LENGTH = 32;
const NONCE_LENGTH = 12;

// ─── Mnemonic Encryption ─────────────────────────────────────────────────

export function encryptMnemonic(
	mnemonic: string,
	passphrase: string,
): { ciphertext: Uint8Array; salt: Uint8Array; nonce: Uint8Array } {
	const salt = randomBytes(SALT_LENGTH);
	const nonce = randomBytes(NONCE_LENGTH);
	const key = scrypt(passphrase, salt, {
		N: SCRYPT_N,
		r: SCRYPT_R,
		p: SCRYPT_P,
		dkLen: SCRYPT_DKLEN,
	});
	const cipher = gcm(key, nonce);
	const ciphertext = cipher.encrypt(new TextEncoder().encode(mnemonic));
	return { ciphertext, salt, nonce };
}

export function decryptMnemonic(
	ciphertext: Uint8Array,
	salt: Uint8Array,
	nonce: Uint8Array,
	passphrase: string,
): string {
	try {
		const key = scrypt(passphrase, salt, {
			N: SCRYPT_N,
			r: SCRYPT_R,
			p: SCRYPT_P,
			dkLen: SCRYPT_DKLEN,
		});
		const cipher = gcm(key, nonce);
		const plaintext = cipher.decrypt(ciphertext);
		return new TextDecoder().decode(plaintext);
	} catch (e) {
		throw new OWSError(
			OWSErrorCode.EXPORT_FAILED,
			'Failed to decrypt mnemonic — wrong passphrase?',
			e,
		);
	}
}

// ─── Mnemonic Utilities ──────────────────────────────────────────────────

/**
 * Generate a BIP-39 mnemonic phrase.
 * @param words - 12 or 24 (default: 12)
 */
export function generateMnemonic(words: number = 12): string {
	return bip39Generate(wordlist, words === 24 ? 256 : 128);
}

/** Validate a BIP-39 mnemonic. */
export function isValidMnemonic(mnemonic: string): boolean {
	return validateMnemonic(mnemonic, wordlist);
}

// ─── Mnemonic → Private Key ──────────────────────────────────────────────

/**
 * Derive a private key from a BIP-39 mnemonic, ready to import into Ika.
 *
 * - **secp256k1 / secp256r1**: BIP-32 derivation at `m/44'/60'/0'/0/{index}`.
 *   Returns the raw 32-byte private key.
 *
 * - **ed25519**: SLIP-0010 derivation at `m/44'/501'/{index}'/0'`,
 *   then SHA-512 + clamp + reduce mod L (RFC 8032). The resulting
 *   public key matches Phantom/Solflare for the same mnemonic.
 *
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param curve - Target curve
 * @param index - Account index (default: 0)
 */
export function derivePrivateKeyFromMnemonic(
	mnemonic: string,
	curve: Curve,
	index: number = 0,
): Uint8Array {
	if (!isValidMnemonic(mnemonic)) {
		throw new OWSError(OWSErrorCode.INVALID_INPUT, 'Invalid BIP-39 mnemonic');
	}

	const seed = mnemonicToSeedSync(mnemonic);

	if (curve === Curve.ED25519) {
		const seedHex = Buffer.from(seed).toString('hex');
		const { key } = derivePath(`m/44'/501'/${index}'/0'`, seedHex);
		return ed25519SeedToPrivateKey(new Uint8Array(key));
	}

	// BIP-32 for secp256k1 / secp256r1.
	const master = HDKey.fromMasterSeed(seed);
	const path = `m/44'/60'/0'/0/${index}`;
	const derived = master.derive(path);
	if (!derived.privateKey) {
		throw new OWSError(OWSErrorCode.INVALID_INPUT, `Failed to derive key at path ${path}`);
	}
	return derived.privateKey;
}

// ─── Ed25519 Seed Conversion ─────────────────────────────────────────────

/** Ed25519 curve order L (little-endian integer). */
const ED25519_L = BigInt(
	'7237005577332262213973186563042994240857116359379907606001950938285454250989',
);

/**
 * Convert an ed25519 seed (32 bytes) to the private key scalar that
 * matches standard wallet implementations (Phantom, Solflare, Sui Wallet).
 *
 * Per RFC 8032: SHA-512(seed) → first 32 bytes → clamp → reduce mod L.
 *
 * The clamp + reduce produces the same public key as
 * `nacl.sign.keyPair.fromSeed(seed)` because `(clamped mod L) * G`
 * equals `clamped * G` (point multiplication is mod L by definition).
 *
 * The final mod L reduction ensures the scalar passes the Ika WASM's
 * canonical check (`scalar < L`) without requiring any changes to the
 * cryptography crate.
 *
 * @example
 * ```ts
 * // Solana: SLIP-0010 derivation → seed → private key → import
 * const seed = derivePath("m/44'/501'/0'/0'", mnemonicSeedHex).key;
 * const privateKey = ed25519SeedToPrivateKey(seed);
 * const wallet = await provider.createWallet('sol', bytesToHex(privateKey), {
 *   curve: Curve.ED25519,
 * });
 * // Address matches Phantom for the same mnemonic.
 * ```
 */
export function ed25519SeedToPrivateKey(seed: Uint8Array): Uint8Array {
	const h = sha512(seed);
	const clamped = h.slice(0, 32);
	clamped[0] &= 248;
	clamped[31] &= 127;
	clamped[31] |= 64;

	// Reduce mod L so the WASM accepts it (strict canonical scalar check).
	// Mathematically identical: (x mod L) * G = x * G for any x.
	let n = 0n;
	for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(clamped[i]!);
	n = n % ED25519_L;

	const result = new Uint8Array(32);
	for (let i = 0; i < 32; i++) {
		result[i] = Number(n & 0xffn);
		n >>= 8n;
	}
	return result;
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
