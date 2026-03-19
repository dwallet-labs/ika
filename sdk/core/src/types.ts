// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Represents a network encryption key with its metadata.
 */
export interface NetworkEncryptionKey {
	/** The unique identifier of the encryption key */
	id: string;
	/** The epoch when this encryption key was created */
	epoch: number;
	/** The public output ID for this encryption key */
	networkDKGOutputID: string;
	/** The reconfiguration output ID associated with this encryption key */
	reconfigurationOutputID: string | undefined;
}

/**
 * Options for encryption key selection in protocol public parameters.
 */
export interface EncryptionKeyOptions {
	/** Specific encryption key ID to use */
	encryptionKeyID?: string;
	/** Whether to automatically detect the encryption key from the dWallet */
	autoDetect?: boolean;
}

export const DWalletKind = {
	ZeroTrust: 'zero-trust',
	ImportedKey: 'imported-key',
	ImportedKeyShared: 'imported-key-shared',
	Shared: 'shared',
} as const;

export type DWalletKind = (typeof DWalletKind)[keyof typeof DWalletKind];

/**
 * Hash algorithms supported by the Ika network.
 *
 * **Valid Combinations:**
 * - `KECCAK256`, `SHA256`, `DoubleSHA256`: Compatible with ECDSASecp256k1
 * - `SHA256`: Compatible with Taproot
 * - `SHA256`, `DoubleSHA256`: Compatible with ECDSASecp256r1
 * - `SHA512`: Compatible with EdDSA
 * - `Merlin`: Compatible with SchnorrkelSubstrate
 */
export const Hash = {
	/** KECCAK256 (SHA3) - Compatible with: ECDSASecp256k1 */
	KECCAK256: 'KECCAK256',
	/** SHA256 - Compatible with: ECDSASecp256k1, Taproot, ECDSASecp256r1 */
	SHA256: 'SHA256',
	/** Double SHA256: h(x) = sha256(sha256(x)) - Compatible with: ECDSASecp256k1, ECDSASecp256r1 */
	DoubleSHA256: 'DoubleSHA256',
	/** SHA512 - Compatible with: EdDSA only */
	SHA512: 'SHA512',
	/** Merlin (STROBE-based transcript construction) - Compatible with: SchnorrkelSubstrate only */
	Merlin: 'Merlin',
} as const;

export type Hash = (typeof Hash)[keyof typeof Hash];

/**
 * Elliptic curves supported by the Ika network.
 * Each curve is associated with specific signature algorithms.
 */
export const Curve = {
	/** secp256k1 - Used by: ECDSASecp256k1, Taproot */
	SECP256K1: 'SECP256K1',
	/** Ristretto - Used by: SchnorrkelSubstrate */
	RISTRETTO: 'RISTRETTO',
	/** Ed25519 - Used by: EdDSA */
	ED25519: 'ED25519',
	/** secp256r1 (P-256) - Used by: ECDSASecp256r1 */
	SECP256R1: 'SECP256R1',
} as const;

export type Curve = (typeof Curve)[keyof typeof Curve];

/**
 * Signature algorithms supported by the Ika network.
 *
 * **Valid Hash Combinations:**
 * - `ECDSASecp256k1`: KECCAK256, SHA256, DoubleSHA256
 * - `Taproot`: SHA256 only
 * - `ECDSASecp256r1`: SHA256, DoubleSHA256
 * - `EdDSA`: SHA512 only
 * - `SchnorrkelSubstrate`: Merlin only
 */
export const SignatureAlgorithm = {
	/** ECDSA with secp256k1 curve - Valid hashes: KECCAK256, SHA256, DoubleSHA256 */
	ECDSASecp256k1: 'ECDSASecp256k1',
	/** Taproot (Bitcoin) - Valid hash: SHA256 only */
	Taproot: 'Taproot',
	/** ECDSA with secp256r1 (P-256) curve - Valid hashes: SHA256, DoubleSHA256 */
	ECDSASecp256r1: 'ECDSASecp256r1',
	/** EdDSA (Ed25519) - Valid hash: SHA512 only */
	EdDSA: 'EdDSA',
	/** Schnorrkel/Ristretto (Substrate) - Valid hash: Merlin only */
	SchnorrkelSubstrate: 'SchnorrkelSubstrate',
} as const;

export type SignatureAlgorithm = (typeof SignatureAlgorithm)[keyof typeof SignatureAlgorithm];
