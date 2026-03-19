// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { ed25519 } from '@noble/curves/ed25519.js';
import { bech32 } from '@scure/base';

import { bytesToHex, hexToBytes } from './utils.js';

const SUI_PRIVATE_KEY_PREFIX = 'suiprivkey';

/**
 * Chain-agnostic Ed25519 keypair implementation using @noble/curves.
 *
 * This replaces `@mysten/sui/keypairs/ed25519` for the core library,
 * providing the same signing/verification primitives without any
 * chain-specific dependencies.
 */
export class Ed25519Keypair {
	/** The 32-byte private key (seed). */
	readonly #secretKey: Uint8Array;
	/** The 32-byte public key. */
	readonly publicKey: Uint8Array;

	private constructor(secretKey: Uint8Array) {
		this.#secretKey = secretKey;
		this.publicKey = ed25519.getPublicKey(secretKey);
	}

	/**
	 * Derive a keypair from a 32-byte seed.
	 *
	 * @param seed - 32-byte seed
	 */
	static fromSeed(seed: Uint8Array): Ed25519Keypair {
		if (seed.length !== 32) {
			throw new Error('Ed25519 seed must be 32 bytes');
		}
		return new Ed25519Keypair(seed);
	}

	/**
	 * Derive a keypair from a hex-encoded seed string.
	 *
	 * @param hexSeed - Hex-encoded 32-byte seed (with or without 0x prefix)
	 */
	static deriveKeypairFromSeed(hexSeed: string): Ed25519Keypair {
		return Ed25519Keypair.fromSeed(hexToBytes(hexSeed));
	}

	/**
	 * Restore a keypair from a secret key string.
	 *
	 * Accepts two formats:
	 * - **Hex string**: 64 hex characters (the V3 / chain-agnostic format)
	 * - **Bech32 string**: `suiprivkey1...` (the V1/V2 Sui legacy format,
	 *   which encodes `flag_byte || 32_byte_secret_key`)
	 *
	 * @param secretKey - Hex-encoded or Bech32-encoded secret key
	 */
	static fromSecretKey(secretKey: string): Ed25519Keypair {
		if (secretKey.startsWith(SUI_PRIVATE_KEY_PREFIX)) {
			return Ed25519Keypair.fromSeed(decodeSuiPrivateKey(secretKey));
		}
		return Ed25519Keypair.fromSeed(hexToBytes(secretKey));
	}

	/**
	 * Returns the secret key as a hex-encoded string.
	 * Can be passed to `fromSecretKey()` to restore the keypair.
	 *
	 * @security This returns raw secret key material. Only use for
	 * serialization to encrypted storage. Never log or transmit.
	 */
	getSecretKey(): string {
		return bytesToHex(this.#secretKey);
	}

	/**
	 * Returns the raw 32-byte public key.
	 */
	getPublicKeyBytes(): Uint8Array {
		return this.publicKey;
	}

	/**
	 * Sign a message with this keypair.
	 *
	 * @param message - The message bytes to sign
	 * @returns The 64-byte Ed25519 signature
	 */
	async sign(message: Uint8Array): Promise<Uint8Array> {
		return ed25519.sign(message, this.#secretKey);
	}

	/**
	 * Verify a signature against a message using this keypair's public key.
	 *
	 * @param message - The message bytes
	 * @param signature - The signature to verify
	 * @returns True if the signature is valid
	 */
	async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
		return ed25519.verify(signature, message, this.publicKey);
	}

	/**
	 * Verify a signature against a message using an arbitrary public key.
	 *
	 * @param publicKey - The 32-byte Ed25519 public key
	 * @param message - The message bytes
	 * @param signature - The signature to verify
	 * @returns True if the signature is valid
	 */
	static verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
		return ed25519.verify(signature, message, publicKey);
	}
}

/**
 * Decode a Sui Bech32-encoded private key (`suiprivkey1...`) to raw
 * 32-byte Ed25519 secret key bytes.
 *
 * The encoded payload is `flag_byte || 32_byte_secret_key`.
 * Flag `0x00` = Ed25519, which is the only scheme we support here.
 *
 * @param encoded - Bech32-encoded private key string
 * @returns The raw 32-byte secret key
 */
function decodeSuiPrivateKey(encoded: string): Uint8Array {
	const { prefix, words } = bech32.decode(encoded as `${string}1${string}`);
	if (prefix !== SUI_PRIVATE_KEY_PREFIX) {
		throw new Error(`Invalid private key prefix: expected '${SUI_PRIVATE_KEY_PREFIX}', got '${prefix}'`);
	}
	const extendedSecretKey = new Uint8Array(bech32.fromWords(words));
	const flag = extendedSecretKey[0];
	// 0x00 = Ed25519
	if (flag !== 0x00) {
		throw new Error(`Unsupported key scheme flag: ${flag}. Only Ed25519 (0x00) is supported.`);
	}
	return extendedSecretKey.slice(1);
}
