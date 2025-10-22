// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve, Hash, SignatureAlgorithm } from './types.js';

/**
 * Supported hash algorithms for each signature algorithm.
 *
 * Mapping:
 * - secp256k1 (ECDSASecp256k1): SHA2 (SHA256, DoubleSHA256), SHA3 (KECCAK256)
 * - Taproot: SHA256 only
 * - secp256r1 (ECDSASecp256r1): SHA2 (SHA256, DoubleSHA256) only
 * - EdDSA (Ed25519): SHA512 only
 * - SchnorrkelSubstrate (Ristretto): Merlin only
 */
const VALID_HASH_SIGNATURE_COMBINATIONS: Record<SignatureAlgorithm, readonly Hash[]> = {
	[SignatureAlgorithm.ECDSASecp256k1]: [Hash.KECCAK256, Hash.SHA256, Hash.DoubleSHA256],
	[SignatureAlgorithm.Taproot]: [Hash.SHA256],
	[SignatureAlgorithm.ECDSASecp256r1]: [Hash.SHA256],
	[SignatureAlgorithm.EdDSA]: [Hash.SHA512],
	[SignatureAlgorithm.SchnorrkelSubstrate]: [Hash.Merlin],
} as const;

/**
 * Maps signature algorithms to their corresponding curves
 */
const SIGNATURE_ALGORITHM_TO_CURVE: Record<SignatureAlgorithm, Curve> = {
	[SignatureAlgorithm.ECDSASecp256k1]: Curve.SECP256K1,
	[SignatureAlgorithm.Taproot]: Curve.SECP256K1,
	[SignatureAlgorithm.ECDSASecp256r1]: Curve.SECP256R1,
	[SignatureAlgorithm.EdDSA]: Curve.ED25519,
	[SignatureAlgorithm.SchnorrkelSubstrate]: Curve.RISTRETTO,
} as const;

/**
 * Get human-readable name for a hash algorithm
 */
export function getHashName(hash: Hash): string {
	switch (hash) {
		case Hash.KECCAK256:
			return 'KECCAK256 (SHA3)';
		case Hash.SHA256:
			return 'SHA256';
		case Hash.DoubleSHA256:
			return 'DoubleSHA256';
		case Hash.SHA512:
			return 'SHA512';
		case Hash.Merlin:
			return 'Merlin';
		default:
			return `Unknown Hash (${hash})`;
	}
}

/**
 * Get human-readable name for a signature algorithm
 */
export function getSignatureAlgorithmName(signatureAlgorithm: SignatureAlgorithm): string {
	switch (signatureAlgorithm) {
		case SignatureAlgorithm.ECDSASecp256k1:
			return 'ECDSASecp256k1';
		case SignatureAlgorithm.Taproot:
			return 'Taproot';
		case SignatureAlgorithm.ECDSASecp256r1:
			return 'ECDSASecp256r1';
		case SignatureAlgorithm.EdDSA:
			return 'EdDSA';
		case SignatureAlgorithm.SchnorrkelSubstrate:
			return 'SchnorrkelSubstrate (Ristretto)';
		default:
			return `Unknown SignatureAlgorithm (${signatureAlgorithm})`;
	}
}

/**
 * Get human-readable name for a curve
 */
export function getCurveName(curve: Curve): string {
	switch (curve) {
		case Curve.SECP256K1:
			return 'secp256k1';
		case Curve.SECP256R1:
			return 'secp256r1';
		case Curve.ED25519:
			return 'Ed25519';
		case Curve.RISTRETTO:
			return 'Ristretto';
		default:
			return `Unknown Curve (${curve})`;
	}
}

/**
 * Runtime validation: Checks if the hash and signature algorithm combination is valid.
 *
 * @param hash - The hash algorithm to validate
 * @param signatureAlgorithm - The signature algorithm to validate
 * @throws {Error} If the combination is not supported
 */
export function validateHashSignatureCombination(
	hash: Hash,
	signatureAlgorithm: SignatureAlgorithm,
): void {
	const validHashes = VALID_HASH_SIGNATURE_COMBINATIONS[signatureAlgorithm];

	if (!validHashes.includes(hash)) {
		const supportedHashNames = validHashes.map(getHashName).join(', ');
		throw new Error(
			`Invalid hash and signature algorithm combination: ` +
				`${getSignatureAlgorithmName(signatureAlgorithm)} does not support ${getHashName(hash)}. ` +
				`Supported hash algorithms for ${getSignatureAlgorithmName(signatureAlgorithm)}: ${supportedHashNames}`,
		);
	}
}

/**
 * Runtime validation: Checks if the curve matches the signature algorithm.
 *
 * @param curve - The curve to validate
 * @param signatureAlgorithm - The signature algorithm to validate
 * @throws {Error} If the curve does not match the signature algorithm
 */
export function validateCurveSignatureAlgorithm(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
): void {
	const expectedCurve = SIGNATURE_ALGORITHM_TO_CURVE[signatureAlgorithm];

	if (curve !== expectedCurve) {
		throw new Error(
			`Invalid curve and signature algorithm combination: ` +
				`${getSignatureAlgorithmName(signatureAlgorithm)} requires ${getCurveName(expectedCurve)}, ` +
				`but ${getCurveName(curve)} was provided.`,
		);
	}
}

/**
 * Type-safe hash-signature combinations.
 * Use this for compile-time type checking.
 */
export type ValidHashForSignature<S extends SignatureAlgorithm> =
	S extends typeof SignatureAlgorithm.ECDSASecp256k1
		? typeof Hash.KECCAK256 | typeof Hash.SHA256 | typeof Hash.DoubleSHA256
		: S extends typeof SignatureAlgorithm.Taproot
			? typeof Hash.SHA256
			: S extends typeof SignatureAlgorithm.ECDSASecp256r1
				? typeof Hash.SHA256 | typeof Hash.DoubleSHA256
				: S extends typeof SignatureAlgorithm.EdDSA
					? typeof Hash.SHA512
					: S extends typeof SignatureAlgorithm.SchnorrkelSubstrate
						? typeof Hash.Merlin
						: never;

/**
 * Type guard to check if a hash is valid for a signature algorithm at compile time
 */
export function isValidHashForSignature<S extends SignatureAlgorithm>(
	hash: Hash,
	signatureAlgorithm: S,
): hash is ValidHashForSignature<S> {
	const validHashes = VALID_HASH_SIGNATURE_COMBINATIONS[signatureAlgorithm];
	return validHashes.includes(hash);
}

/**
 * Compile-time validated parameters for signing operations.
 * This ensures that only valid hash/signature algorithm combinations are accepted.
 */
export type ValidatedSigningParams<S extends SignatureAlgorithm> = {
	hashScheme: ValidHashForSignature<S>;
	signatureAlgorithm: S;
};

/**
 * Helper to create validated signing parameters with compile-time type checking.
 * This will produce a compile error if an invalid hash/signature combination is provided.
 *
 * @example
 * // Valid - compiles successfully
 * const params = createValidatedSigningParams(Hash.SHA256, SignatureAlgorithm.ECDSASecp256k1);
 *
 * @example
 * // Invalid - will cause a compile error
 * const params = createValidatedSigningParams(Hash.SHA512, SignatureAlgorithm.ECDSASecp256k1);
 */
export function createValidatedSigningParams<S extends SignatureAlgorithm>(
	hashScheme: ValidHashForSignature<S>,
	signatureAlgorithm: S,
): ValidatedSigningParams<S> {
	// Runtime validation as well
	validateHashSignatureCombination(hashScheme, signatureAlgorithm);
	return { hashScheme, signatureAlgorithm };
}

/**
 * Get a list of all valid hash algorithms for a given signature algorithm.
 * Useful for displaying options to users or generating documentation.
 *
 * @param signatureAlgorithm - The signature algorithm to get valid hashes for
 * @returns Array of valid hash names
 *
 * @example
 * const validHashes = getValidHashesForSignatureAlgorithm(SignatureAlgorithm.ECDSASecp256k1);
 * // Returns: ['KECCAK256 (SHA3)', 'SHA256', 'DoubleSHA256']
 */
export function getValidHashesForSignatureAlgorithm(
	signatureAlgorithm: SignatureAlgorithm,
): string[] {
	const validHashes = VALID_HASH_SIGNATURE_COMBINATIONS[signatureAlgorithm];
	return validHashes.map(getHashName);
}

/**
 * Get a comprehensive summary of all valid hash/signature algorithm combinations.
 * Useful for documentation or displaying help information.
 *
 * @returns A map of signature algorithm names to their valid hash names
 *
 * @example
 * const summary = getValidCombinationsSummary();
 * console.log(summary);
 * // {
 * //   'ECDSASecp256k1': ['KECCAK256 (SHA3)', 'SHA256', 'DoubleSHA256'],
 * //   'Taproot': ['KECCAK256 (SHA3)', 'SHA256', 'DoubleSHA256'],
 * //   ...
 * // }
 */
export function getValidCombinationsSummary(): Record<string, string[]> {
	const summary: Record<string, string[]> = {};

	for (const [sigAlg, validHashes] of Object.entries(VALID_HASH_SIGNATURE_COMBINATIONS)) {
		const sigAlgNum = parseInt(sigAlg, 10) as SignatureAlgorithm;
		summary[getSignatureAlgorithmName(sigAlgNum)] = validHashes.map(getHashName);
	}

	return summary;
}
