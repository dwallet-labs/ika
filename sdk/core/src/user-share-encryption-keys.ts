// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs } from '@mysten/bcs';
import { keccak_256 } from '@noble/hashes/sha3.js';

import { createClassGroupsKeypair, userAndNetworkDKGOutputMatch } from './cryptography.js';
import { Ed25519Keypair } from './ed25519.js';
import { fromCurveToNumber, fromNumberToCurve } from './hash-signature-validation.js';
import type { Curve } from './types.js';
import { bytesToHex, encodeToASCII } from './utils.js';
import { decrypt_user_share } from './wasm-loader.js';

/**
 * BCS enum for serializing/deserializing UserShareEncryptionKeys.
 *
 * - `V1`: Legacy hash (curve byte always 0), secret key as Bech32 string.
 * - `V2`: Fixed hash (correct curve byte), secret key as Bech32 string.
 * - `V3`: Fixed hash, secret key as hex string. Chain-agnostic format.
 *
 * Deserialization handles all three variants transparently — the
 * Ed25519Keypair auto-detects Bech32 vs hex encoding.
 * Serialization always writes V3.
 */
export const VersionedUserShareEncryptionKeysBcs = bcs.enum('VersionedUserShareEncryptionKeys', {
	V1: bcs.struct('UserShareEncryptionKeysV1', {
		encryptionKey: bcs.vector(bcs.u8()),
		decryptionKey: bcs.vector(bcs.u8()),
		secretShareSigningSecretKey: bcs.string(),
		curve: bcs.u64(),
	}),
	V2: bcs.struct('UserShareEncryptionKeysV2', {
		encryptionKey: bcs.vector(bcs.u8()),
		decryptionKey: bcs.vector(bcs.u8()),
		secretShareSigningSecretKey: bcs.string(),
		curve: bcs.u32(),
	}),
	V3: bcs.struct('UserShareEncryptionKeysV3', {
		encryptionKey: bcs.vector(bcs.u8()),
		decryptionKey: bcs.vector(bcs.u8()),
		secretShareSigningSecretKey: bcs.string(),
		curve: bcs.u32(),
		legacyHash: bcs.bool(),
	}),
});

/**
 * Manages encryption/decryption keys and Ed25519 signing keypairs for
 * encrypting, decrypting, and authorizing dWallet user secret shares.
 *
 * ## Key derivation
 *
 * All keys are deterministically derived from a single 32-byte root seed
 * via domain-separated `keccak256` hashes:
 *
 * ```
 * seed = keccak256(ASCII(domain) || curveByte || rootSeed)
 * ```
 *
 * - **Class-groups keypair** — encrypts/decrypts the user secret share.
 * - **Ed25519 signing keypair** — signs the encryption key and dWallet
 *   public outputs to prove ownership and authorize operations.
 *
 * ## Legacy vs fixed hash
 *
 * An earlier version had a bug where the curve byte was always `0`
 * regardless of the actual curve (the `Curve` string enum was passed to
 * `Uint8Array.from()`, which coerced it to `NaN` → `0`).
 * This only matters for non-SECP256K1 curves (whose curve number is
 * already `0`).
 *
 * - Use {@link fromRootSeedKey} for new registrations (fixed hash).
 * - Use {@link fromRootSeedKeyLegacyHash} only to reproduce keys that
 *   were registered on-chain before the fix.
 *
 * Serialization via {@link toShareEncryptionKeysBytes} always writes
 * `V3` (chain-agnostic hex format). Deserialization handles all three
 * variants: `V1` (legacy Bech32), `V2` (fixed Bech32), `V3` (hex).
 */
export class UserShareEncryptionKeys {
	/** Class-groups public encryption key (encrypts secret shares). */
	readonly encryptionKey: Uint8Array;
	/**
	 * Class-groups private decryption key (decrypts secret shares).
	 *
	 * @security This is sensitive key material. Do not expose or log.
	 * Use {@link decryptSecretShare} for decryption operations.
	 */
	readonly #decryptionKey: Uint8Array;
	/** Ed25519 keypair used to sign encryption keys and dWallet outputs. */
	#signingKeypair: Ed25519Keypair;
	/** Curve these keys were generated for. */
	readonly curve: Curve;
	/**
	 * `true` when the keys were derived with the legacy (buggy) hash that
	 * always uses `0` as the curve byte.
	 */
	readonly legacyHash: boolean;

	/** Domain separators used in the keccak256 key derivation hash. */
	static domainSeparators = {
		classGroups: 'CLASS_GROUPS_DECRYPTION_KEY_V1',
		encryptionSignerKey: 'ED25519_SIGNING_KEY_V1',
	};

	private constructor(
		encryptionKey: Uint8Array,
		decryptionKey: Uint8Array,
		signingKeypair: Ed25519Keypair,
		curve: Curve,
		legacyHash: boolean = false,
	) {
		this.encryptionKey = encryptionKey;
		this.#decryptionKey = decryptionKey;
		this.#signingKeypair = signingKeypair;
		this.curve = curve;
		this.legacyHash = legacyHash;
	}

	// -----------------------------------------------------------------------
	// Construction
	// -----------------------------------------------------------------------

	/**
	 * Create a `UserShareEncryptionKeys` from pre-existing key material.
	 *
	 * This is intended for chain SDKs that need to construct instances from
	 * deserialized legacy formats (e.g., Sui's V1/V2 Bech32-encoded keys).
	 *
	 * @param encryptionKey - Class-groups public encryption key
	 * @param decryptionKey - Class-groups private decryption key
	 * @param signingSecretKeyHex - Ed25519 signing secret key as hex string
	 * @param curve - The curve these keys were generated for
	 * @param legacyHash - Whether the legacy hash derivation was used
	 */
	static fromKeyMaterial(
		encryptionKey: Uint8Array,
		decryptionKey: Uint8Array,
		signingSecretKeyHex: string,
		curve: Curve,
		legacyHash: boolean,
	): UserShareEncryptionKeys {
		const signingKeypair = Ed25519Keypair.fromSecretKey(signingSecretKeyHex);
		return new UserShareEncryptionKeys(
			encryptionKey,
			decryptionKey,
			signingKeypair,
			curve,
			legacyHash,
		);
	}

	/**
	 * Derives encryption keys from a root seed using the **fixed** hash
	 * (`keccak256(domain || curveNumber || seed)`).
	 *
	 * This is the default and recommended constructor for all new key
	 * registrations.
	 */
	static async fromRootSeedKey(
		rootSeedKey: Uint8Array,
		curve: Curve,
	): Promise<UserShareEncryptionKeys> {
		return UserShareEncryptionKeys.#createFromSeed(rootSeedKey, curve, false);
	}

	/**
	 * Derives encryption keys from a root seed using the **legacy** hash
	 * (`keccak256(domain || 0 || seed)` — curve byte is always `0`).
	 *
	 * Only needed to reproduce keys that were registered on-chain before
	 * the curve-byte fix. SECP256K1 is unaffected (its curve number is
	 * already `0`), so this only matters for SECP256R1, ED25519, and
	 * RISTRETTO keys.
	 *
	 * @deprecated Register new keys with {@link fromRootSeedKey} instead.
	 */
	static async fromRootSeedKeyLegacyHash(
		rootSeedKey: Uint8Array,
		curve: Curve,
	): Promise<UserShareEncryptionKeys> {
		return UserShareEncryptionKeys.#createFromSeed(rootSeedKey, curve, true);
	}

	/**
	 * Shared construction logic — derives class-groups and Ed25519 keypairs
	 * from a root seed, using either the fixed or legacy hash function.
	 */
	static async #createFromSeed(
		rootSeedKey: Uint8Array,
		curve: Curve,
		legacyHash: boolean,
	): Promise<UserShareEncryptionKeys> {
		const hashFn = legacyHash ? UserShareEncryptionKeys.hashLegacy : UserShareEncryptionKeys.hash;

		const classGroupsSeed = hashFn(
			UserShareEncryptionKeys.domainSeparators.classGroups,
			rootSeedKey,
			curve,
		);

		const encryptionSignerKeySeed = hashFn(
			UserShareEncryptionKeys.domainSeparators.encryptionSignerKey,
			rootSeedKey,
			curve,
		);

		const classGroupsKeypair = await createClassGroupsKeypair(classGroupsSeed, curve);
		const signingKeypair = Ed25519Keypair.deriveKeypairFromSeed(
			bytesToHex(encryptionSignerKeySeed),
		);

		return new UserShareEncryptionKeys(
			new Uint8Array(classGroupsKeypair.encryptionKey),
			new Uint8Array(classGroupsKeypair.decryptionKey),
			signingKeypair,
			curve,
			legacyHash,
		);
	}

	// -----------------------------------------------------------------------
	// Serialization / deserialization
	// -----------------------------------------------------------------------

	/**
	 * Restores a `UserShareEncryptionKeys` instance from bytes previously
	 * produced by {@link toShareEncryptionKeysBytes}.
	 *
	 * Supports all BCS variants:
	 * - V1: Legacy hash (implicit), Bech32-encoded secret key
	 * - V2: Fixed hash (implicit), Bech32-encoded secret key
	 * - V3: Explicit legacyHash flag, hex-encoded secret key (chain-agnostic)
	 *
	 * `Ed25519Keypair.fromSecretKey` auto-detects the string format
	 * (hex vs Bech32), so all variants are handled transparently.
	 */
	static fromShareEncryptionKeysBytes(
		shareEncryptionKeysBytes: Uint8Array,
	): UserShareEncryptionKeys {
		const { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve, legacyHash } =
			this.#parseShareEncryptionKeys(shareEncryptionKeysBytes);

		const signingKeypair = Ed25519Keypair.fromSecretKey(secretShareSigningSecretKey);

		return new UserShareEncryptionKeys(
			encryptionKey,
			decryptionKey,
			signingKeypair,
			curve,
			legacyHash,
		);
	}

	/**
	 * Serializes these keys to V3 BCS bytes (chain-agnostic hex format).
	 *
	 * The output is suitable for persistent storage and can be restored
	 * with {@link fromShareEncryptionKeysBytes}.
	 *
	 * @security The output contains **unencrypted secret key material**
	 * (class-groups decryption key and Ed25519 signing key). Store the
	 * result encrypted at rest — never persist to localStorage, logs,
	 * or unencrypted databases.
	 */
	toShareEncryptionKeysBytes(): Uint8Array {
		return this.#serializeShareEncryptionKeys();
	}

	// -----------------------------------------------------------------------
	// Identity
	// -----------------------------------------------------------------------

	/** Returns the raw bytes of the Ed25519 signing public key. */
	getSigningPublicKeyBytes(): Uint8Array {
		return this.#signingKeypair.getPublicKeyBytes();
	}

	// -----------------------------------------------------------------------
	// Signature operations
	// -----------------------------------------------------------------------

	/**
	 * Sign a message with the Ed25519 signing keypair.
	 *
	 * This is the generic signing primitive. Chain SDKs use this to
	 * implement domain-specific signing operations (e.g., signing dWallet
	 * public outputs for authorization).
	 *
	 * @param message - The message bytes to sign
	 * @returns The Ed25519 signature
	 */
	async sign(message: Uint8Array): Promise<Uint8Array> {
		return await this.#signingKeypair.sign(message);
	}

	/**
	 * Verifies an Ed25519 signature over a message using the signing
	 * public key.
	 */
	async verifySignature(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
		return await this.#signingKeypair.verify(message, signature);
	}

	/**
	 * Signs the encryption key with the Ed25519 signing keypair.
	 * Used to prove ownership when registering the key on-chain.
	 */
	async getEncryptionKeySignature(): Promise<Uint8Array> {
		return await this.#signingKeypair.sign(this.encryptionKey);
	}

	// -----------------------------------------------------------------------
	// Decryption
	// -----------------------------------------------------------------------

	/**
	 * Decrypt an encrypted user secret key share.
	 *
	 * This is the low-level decryption primitive. Chain SDKs should wrap this
	 * with domain-specific verification (e.g., checking dWallet state and
	 * signature verification) before calling.
	 *
	 * @param dWalletPublicOutput - The verified public output of the dWallet
	 * @param encryptedShareAndProof - The encrypted centralized secret share and proof
	 * @param protocolPublicParameters - The protocol public parameters
	 * @returns The decrypted secret share
	 */
	async decryptSecretShare(
		dWalletPublicOutput: Uint8Array,
		encryptedShareAndProof: Uint8Array,
		protocolPublicParameters: Uint8Array,
	): Promise<Uint8Array> {
		return Uint8Array.from(
			await decrypt_user_share(
				fromCurveToNumber(this.curve),
				this.#decryptionKey,
				dWalletPublicOutput,
				encryptedShareAndProof,
				protocolPublicParameters,
			),
		);
	}

	/**
	 * Verify that a user public output matches a network DKG output for this key's curve.
	 *
	 * @param userPublicOutput - The user's public output
	 * @param networkDKGOutput - The network's DKG output
	 * @returns True if the outputs match
	 */
	async verifyDKGOutputMatch(
		userPublicOutput: Uint8Array,
		networkDKGOutput: Uint8Array,
	): Promise<boolean> {
		return userAndNetworkDKGOutputMatch(
			this.curve,
			userPublicOutput,
			networkDKGOutput,
		);
	}

	// -----------------------------------------------------------------------
	// Hash functions
	// -----------------------------------------------------------------------

	/**
	 * Derives a 32-byte seed by hashing:
	 * `keccak256(ASCII(domainSeparator) || curveNumber || rootSeed)`
	 *
	 * This is the correct derivation that includes the actual curve byte.
	 */
	static hash(domainSeparator: string, rootSeed: Uint8Array, curve: Curve): Uint8Array {
		return new Uint8Array(
			keccak_256(
				Uint8Array.from([...encodeToASCII(domainSeparator), fromCurveToNumber(curve), ...rootSeed]),
			),
		);
	}

	/**
	 * Legacy hash: `keccak256(ASCII(domainSeparator) || 0 || rootSeed)`.
	 *
	 * Always uses `0` as the curve byte regardless of the actual curve,
	 * matching the original buggy behavior. Only used internally by
	 * {@link fromRootSeedKeyLegacyHash}.
	 *
	 * @deprecated Use {@link hash} for all new key derivations.
	 */
	static hashLegacy(domainSeparator: string, rootSeed: Uint8Array, _curve: Curve): Uint8Array {
		return new Uint8Array(
			keccak_256(Uint8Array.from([...encodeToASCII(domainSeparator), 0, ...rootSeed])),
		);
	}

	// -----------------------------------------------------------------------
	// Private serialization helpers
	// -----------------------------------------------------------------------

	#serializeShareEncryptionKeys() {
		const fields = {
			encryptionKey: this.encryptionKey,
			decryptionKey: this.#decryptionKey,
			secretShareSigningSecretKey: this.#signingKeypair.getSecretKey(),
			curve: fromCurveToNumber(this.curve),
			legacyHash: this.legacyHash,
		};

		// Always serialize as V3 (chain-agnostic hex format).
		return VersionedUserShareEncryptionKeysBcs.serialize({ V3: fields }).toBytes();
	}

	static #parseShareEncryptionKeys(shareEncryptionKeysBytes: Uint8Array) {
		const parsed = VersionedUserShareEncryptionKeysBcs.parse(shareEncryptionKeysBytes);

		// V1 = legacy hash + Bech32 secret key
		// V2 = fixed hash + Bech32 secret key
		// V3 = hex secret key + explicit legacyHash flag
		// Ed25519Keypair.fromSecretKey auto-detects Bech32 vs hex.
		if (parsed.V1) {
			const { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve } = parsed.V1;
			return {
				encryptionKey: new Uint8Array(encryptionKey),
				decryptionKey: new Uint8Array(decryptionKey),
				secretShareSigningSecretKey,
				curve: fromNumberToCurve(Number(curve)),
				legacyHash: true,
			};
		}

		if (parsed.V2) {
			const { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve } = parsed.V2;
			return {
				encryptionKey: new Uint8Array(encryptionKey),
				decryptionKey: new Uint8Array(decryptionKey),
				secretShareSigningSecretKey,
				curve: fromNumberToCurve(Number(curve)),
				legacyHash: false,
			};
		}

		if (parsed.V3) {
			const { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve, legacyHash } =
				parsed.V3;
			return {
				encryptionKey: new Uint8Array(encryptionKey),
				decryptionKey: new Uint8Array(decryptionKey),
				secretShareSigningSecretKey,
				curve: fromNumberToCurve(Number(curve)),
				legacyHash,
			};
		}

		throw new Error('Failed to parse UserShareEncryptionKeys: no recognized BCS variant');
	}
}
