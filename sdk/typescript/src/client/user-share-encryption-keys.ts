// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { bcs, toHex } from '@mysten/bcs';
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { keccak_256 } from '@noble/hashes/sha3.js';

import {
	createClassGroupsKeypair,
	userAndNetworkDKGOutputMatch,
	verifyAndGetDWalletDKGPublicOutput,
} from './cryptography.js';
import { fromCurveToNumber, fromNumberToCurve } from './hash-signature-validation.js';
import type { Curve, DWallet, EncryptedUserSecretKeyShare, EncryptionKey } from './types.js';
import { encodeToASCII } from './utils.js';
import { decrypt_user_share } from './wasm-loader.js';

/**
 * BCS enum for serializing/deserializing UserShareEncryptionKeys.
 *
 * - `V1`: Keys derived with the legacy hash (curve byte always 0).
 * - `V2`: Keys derived with the fixed hash (correct curve byte).
 *
 * Both variants have the same fields; the variant tag is what distinguishes
 * which hash derivation was used, so deserialization can reconstruct
 * the keys with the right derivation function.
 */
export const VersionedUserShareEncryptionKeysBcs = bcs.enum('VersionedUserShareEncryptionKeys', {
	V1: bcs.struct('UserShareEncryptionKeysV1', {
		encryptionKey: bcs.vector(bcs.u8()),
		decryptionKey: bcs.vector(bcs.u8()),
		secretShareSigningSecretKey: bcs.string(),
		curve: bcs.u32(),
	}),
	V2: bcs.struct('UserShareEncryptionKeysV2', {
		encryptionKey: bcs.vector(bcs.u8()),
		decryptionKey: bcs.vector(bcs.u8()),
		secretShareSigningSecretKey: bcs.string(),
		curve: bcs.u32(),
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
 * Serialization via {@link toShareEncryptionKeysBytes} records which
 * derivation was used (BCS `V1` = legacy, `V2` = fixed), so
 * {@link fromShareEncryptionKeysBytes} always picks the right one.
 */
export class UserShareEncryptionKeys {
	/** Class-groups public encryption key (encrypts secret shares). */
	encryptionKey: Uint8Array;
	/** Class-groups private decryption key (decrypts secret shares). */
	decryptionKey: Uint8Array;
	/** Ed25519 keypair used to sign encryption keys and dWallet outputs. */
	#encryptedSecretShareSigningKeypair: Ed25519Keypair;
	/** Curve these keys were generated for. */
	curve: Curve;
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
		secretShareSigningSecretKey: Ed25519Keypair,
		curve: Curve,
		legacyHash: boolean = false,
	) {
		this.encryptionKey = encryptionKey;
		this.decryptionKey = decryptionKey;
		this.#encryptedSecretShareSigningKeypair = secretShareSigningSecretKey;
		this.curve = curve;
		this.legacyHash = legacyHash;
	}

	// -----------------------------------------------------------------------
	// Construction
	// -----------------------------------------------------------------------

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
		const encryptionSignerKey = Ed25519Keypair.deriveKeypairFromSeed(
			toHex(encryptionSignerKeySeed),
		);

		return new UserShareEncryptionKeys(
			new Uint8Array(classGroupsKeypair.encryptionKey),
			new Uint8Array(classGroupsKeypair.decryptionKey),
			encryptionSignerKey,
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
	 * The BCS variant (`V1` vs `V2`) determines whether the legacy or
	 * fixed hash was used, so the returned instance always has the correct
	 * {@link legacyHash} flag.
	 */
	static fromShareEncryptionKeysBytes(
		shareEncryptionKeysBytes: Uint8Array,
	): UserShareEncryptionKeys {
		const { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve, legacyHash } =
			this.#parseShareEncryptionKeys(shareEncryptionKeysBytes);

		const secretShareSigningKeypair = Ed25519Keypair.fromSecretKey(secretShareSigningSecretKey);

		return new UserShareEncryptionKeys(
			encryptionKey,
			decryptionKey,
			secretShareSigningKeypair,
			curve,
			legacyHash,
		);
	}

	/**
	 * Serializes these keys to bytes (BCS `V1` for legacy, `V2` for fixed).
	 *
	 * The output is suitable for persistent storage and can be restored
	 * with {@link fromShareEncryptionKeysBytes}.
	 */
	toShareEncryptionKeysBytes(): Uint8Array {
		return this.#serializeShareEncryptionKeys();
	}

	// -----------------------------------------------------------------------
	// Identity
	// -----------------------------------------------------------------------

	/** Returns the Ed25519 public key of the signing keypair. */
	getPublicKey() {
		return this.#encryptedSecretShareSigningKeypair.getPublicKey();
	}

	/** Returns the Sui address derived from the signing keypair. */
	getSuiAddress(): string {
		return this.#encryptedSecretShareSigningKeypair.getPublicKey().toSuiAddress();
	}

	/** Returns the raw bytes of the Ed25519 signing public key. */
	getSigningPublicKeyBytes(): Uint8Array {
		return this.#encryptedSecretShareSigningKeypair.getPublicKey().toRawBytes();
	}

	// -----------------------------------------------------------------------
	// Signature operations
	// -----------------------------------------------------------------------

	/**
	 * Verifies an Ed25519 signature over a message using the signing
	 * public key.
	 */
	async verifySignature(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
		return await this.#encryptedSecretShareSigningKeypair.getPublicKey().verify(message, signature);
	}

	/**
	 * Signs the encryption key with the Ed25519 signing keypair.
	 * Used to prove ownership when registering the key on-chain.
	 */
	async getEncryptionKeySignature(): Promise<Uint8Array> {
		return await this.#encryptedSecretShareSigningKeypair.sign(this.encryptionKey);
	}

	/**
	 * Signs the dWallet public output to authorize a newly created dWallet.
	 *
	 * @throws If the dWallet is not in `AwaitingKeyHolderSignature` state,
	 *         or the user public output doesn't match the on-chain output.
	 */
	async getUserOutputSignature(
		dWallet: DWallet,
		userPublicOutput: Uint8Array,
	): Promise<Uint8Array> {
		if (!dWallet.state.AwaitingKeyHolderSignature?.public_output) {
			throw new Error('DWallet is not in awaiting key holder signature state');
		}

		const dWalletPublicOutput = Uint8Array.from(
			dWallet.state.AwaitingKeyHolderSignature?.public_output,
		);

		const isOutputMatch = await userAndNetworkDKGOutputMatch(
			fromNumberToCurve(dWallet.curve),
			userPublicOutput,
			dWalletPublicOutput,
		).catch(() => false);

		if (!isOutputMatch) {
			throw new Error('User public output does not match the DWallet public output');
		}

		return await this.#encryptedSecretShareSigningKeypair.sign(dWalletPublicOutput);
	}

	/**
	 * Signs the dWallet public output for a transferred/shared dWallet.
	 *
	 * Verifies the source encrypted share against the source encryption key
	 * before signing. The source encryption key should be known to the
	 * receiver through a trusted channel — **do not fetch it from the
	 * network without independent verification.**
	 */
	async getUserOutputSignatureForTransferredDWallet(
		dWallet: DWallet,
		sourceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
		sourceEncryptionKey: EncryptionKey,
	): Promise<Uint8Array> {
		const dWalletPublicOutput = await verifyAndGetDWalletDKGPublicOutput(
			dWallet,
			sourceEncryptedUserSecretKeyShare,
			new Ed25519PublicKey(sourceEncryptionKey.signer_public_key),
		);

		return await this.#encryptedSecretShareSigningKeypair.sign(dWalletPublicOutput);
	}

	// -----------------------------------------------------------------------
	// Decryption
	// -----------------------------------------------------------------------

	/**
	 * Decrypts an encrypted user secret key share for a dWallet.
	 *
	 * Performs multi-layer verification before decryption:
	 * 1. Validates the dWallet is active with a public output.
	 * 2. Checks the encrypted share's signature against the signing key.
	 * 3. Decrypts with the class-groups decryption key.
	 * 4. Verifies consistency of the decrypted share against the public output.
	 *
	 * @throws If the dWallet is not active, verification fails, or
	 *         decryption fails.
	 */
	async decryptUserShare(
		dWallet: DWallet,
		encryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
		protocolPublicParameters: Uint8Array,
	): Promise<{
		verifiedPublicOutput: Uint8Array;
		secretShare: Uint8Array;
	}> {
		const dWalletPublicOutput = await verifyAndGetDWalletDKGPublicOutput(
			dWallet,
			encryptedUserSecretKeyShare,
			this.#encryptedSecretShareSigningKeypair.getPublicKey(),
		);

		return {
			verifiedPublicOutput: dWalletPublicOutput,
			secretShare: Uint8Array.from(
				await decrypt_user_share(
					fromCurveToNumber(this.curve),
					this.decryptionKey,
					dWalletPublicOutput,
					Uint8Array.from(encryptedUserSecretKeyShare.encrypted_centralized_secret_share_and_proof),
					protocolPublicParameters,
				),
			),
		};
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
			decryptionKey: this.decryptionKey,
			secretShareSigningSecretKey: this.#encryptedSecretShareSigningKeypair.getSecretKey(),
			curve: fromCurveToNumber(this.curve),
		};

		// Legacy keys serialize as V1, fixed keys as V2.
		return VersionedUserShareEncryptionKeysBcs.serialize(
			this.legacyHash ? { V1: fields } : { V2: fields },
		).toBytes();
	}

	static #parseShareEncryptionKeys(shareEncryptionKeysBytes: Uint8Array) {
		const parsed = VersionedUserShareEncryptionKeysBcs.parse(shareEncryptionKeysBytes);

		// V1 variant → legacy hash was used; V2 → fixed hash.
		const variant = parsed.V1 ?? parsed.V2;
		const legacyHash = !!parsed.V1;
		const { encryptionKey, decryptionKey, secretShareSigningSecretKey, curve } = variant;

		return {
			encryptionKey: new Uint8Array(encryptionKey),
			decryptionKey: new Uint8Array(decryptionKey),
			secretShareSigningSecretKey,
			curve: fromNumberToCurve(Number(curve)),
			legacyHash,
		};
	}
}
