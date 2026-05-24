// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { Curve, Hash, SignatureAlgorithm } from './types.js';

// Valid hash algorithms per signature algorithm (for runtime validation)
const VALID_HASH_SIGNATURE_COMBINATIONS: Record<SignatureAlgorithm, readonly Hash[]> = {
	[SignatureAlgorithm.ECDSASecp256k1]: [Hash.KECCAK256, Hash.SHA256, Hash.DoubleSHA256],
	[SignatureAlgorithm.Taproot]: [Hash.SHA256],
	[SignatureAlgorithm.ECDSASecp256r1]: [Hash.SHA256],
	[SignatureAlgorithm.EdDSA]: [Hash.SHA512],
	[SignatureAlgorithm.SchnorrkelSubstrate]: [Hash.Merlin],
} as const;

// Maps signature algorithms to their curves (for validation)
const SIGNATURE_ALGORITHM_TO_CURVE: Record<SignatureAlgorithm, Curve> = {
	[SignatureAlgorithm.ECDSASecp256k1]: Curve.SECP256K1,
	[SignatureAlgorithm.Taproot]: Curve.SECP256K1,
	[SignatureAlgorithm.ECDSASecp256r1]: Curve.SECP256R1,
	[SignatureAlgorithm.EdDSA]: Curve.ED25519,
	[SignatureAlgorithm.SchnorrkelSubstrate]: Curve.RISTRETTO,
} as const;

// Absolute numbering for signature algorithms (global, not relative to curve)
const SIGNATURE_ALGORITHM_ABSOLUTE_NUMBERS: Record<SignatureAlgorithm, number> = {
	[SignatureAlgorithm.ECDSASecp256k1]: 0,
	[SignatureAlgorithm.Taproot]: 1,
	[SignatureAlgorithm.ECDSASecp256r1]: 2,
	[SignatureAlgorithm.EdDSA]: 3,
	[SignatureAlgorithm.SchnorrkelSubstrate]: 4,
} as const;

// Absolute numbering for hashes (global, not relative to curve/signature)
const HASH_ABSOLUTE_NUMBERS: Record<Hash, number> = {
	[Hash.KECCAK256]: 0,
	[Hash.SHA256]: 1,
	[Hash.DoubleSHA256]: 2,
	[Hash.SHA512]: 3,
	[Hash.Merlin]: 4,
} as const;

// Mirrors Rust SUPPORTED_CURVES_TO_SIGNATURE_ALGORITHMS_TO_HASH_SCHEMES
// Single source of truth for curve -> signature algorithm -> hash number mappings
const CURVE_SIGNATURE_HASH_CONFIG = {
	[Curve.SECP256K1]: {
		curveNumber: 0,
		signatureAlgorithms: {
			[SignatureAlgorithm.ECDSASecp256k1]: {
				signatureAlgorithmNumber: 0,
				hashes: {
					[Hash.KECCAK256]: 0,
					[Hash.SHA256]: 1,
					[Hash.DoubleSHA256]: 2,
				},
			},
			[SignatureAlgorithm.Taproot]: {
				signatureAlgorithmNumber: 1,
				hashes: {
					[Hash.SHA256]: 0,
				},
			},
		},
	},
	[Curve.SECP256R1]: {
		curveNumber: 1,
		signatureAlgorithms: {
			[SignatureAlgorithm.ECDSASecp256r1]: {
				signatureAlgorithmNumber: 0,
				hashes: {
					[Hash.SHA256]: 0,
				},
			},
		},
	},
	[Curve.ED25519]: {
		curveNumber: 2,
		signatureAlgorithms: {
			[SignatureAlgorithm.EdDSA]: {
				signatureAlgorithmNumber: 0,
				hashes: {
					[Hash.SHA512]: 0,
				},
			},
		},
	},
	[Curve.RISTRETTO]: {
		curveNumber: 3,
		signatureAlgorithms: {
			[SignatureAlgorithm.SchnorrkelSubstrate]: {
				signatureAlgorithmNumber: 0,
				hashes: {
					[Hash.Merlin]: 0,
				},
			},
		},
	},
} as const;

type SignatureAlgorithmConfig = {
	signatureAlgorithmNumber: number;
	hashes: Record<string, number>;
};

/** Returns human-readable name for a hash algorithm */
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

/** Returns human-readable name for a signature algorithm */
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

/** Returns human-readable name for a curve */
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
 * Validates hash and signature algorithm combination.
 * @throws {Error} with supported hashes if invalid
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
 * Validates curve matches the signature algorithm.
 * @throws {Error} with expected curve if mismatch
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

/** Compile-time type for valid signature algorithms per curve */
export type ValidSignatureAlgorithmForCurve<C extends Curve> = C extends typeof Curve.SECP256K1
	? typeof SignatureAlgorithm.ECDSASecp256k1 | typeof SignatureAlgorithm.Taproot
	: C extends typeof Curve.SECP256R1
		? typeof SignatureAlgorithm.ECDSASecp256r1
		: C extends typeof Curve.ED25519
			? typeof SignatureAlgorithm.EdDSA
			: C extends typeof Curve.RISTRETTO
				? typeof SignatureAlgorithm.SchnorrkelSubstrate
				: never;

/** Compile-time type for valid hash/signature combinations */
export type ValidHashForSignature<S extends SignatureAlgorithm> =
	S extends typeof SignatureAlgorithm.ECDSASecp256k1
		? typeof Hash.KECCAK256 | typeof Hash.SHA256 | typeof Hash.DoubleSHA256
		: S extends typeof SignatureAlgorithm.Taproot
			? typeof Hash.SHA256
			: S extends typeof SignatureAlgorithm.ECDSASecp256r1
				? typeof Hash.SHA256
				: S extends typeof SignatureAlgorithm.EdDSA
					? typeof Hash.SHA512
					: S extends typeof SignatureAlgorithm.SchnorrkelSubstrate
						? typeof Hash.Merlin
						: never;

/** Type guard: checks if hash is valid for signature algorithm */
export function isValidHashForSignature<S extends SignatureAlgorithm>(
	hash: Hash,
	signatureAlgorithm: S,
): hash is ValidHashForSignature<S> {
	const validHashes = VALID_HASH_SIGNATURE_COMBINATIONS[signatureAlgorithm];
	return validHashes.includes(hash);
}

/** Compile-time validated signing parameters */
export type ValidatedSigningParams<S extends SignatureAlgorithm> = {
	hashScheme: ValidHashForSignature<S>;
	signatureAlgorithm: S;
};

/**
 * Creates validated signing params with compile-time checking.
 * @example
 * createValidatedSigningParams(Hash.SHA256, SignatureAlgorithm.ECDSASecp256k1); // OK
 * createValidatedSigningParams(Hash.SHA512, SignatureAlgorithm.ECDSASecp256k1); // Compile error
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
 * Returns array of valid hash names for signature algorithm.
 * @example getValidHashesForSignatureAlgorithm(SignatureAlgorithm.ECDSASecp256k1)
 * // => ['KECCAK256 (SHA3)', 'SHA256', 'DoubleSHA256']
 */
export function getValidHashesForSignatureAlgorithm(
	signatureAlgorithm: SignatureAlgorithm,
): string[] {
	const validHashes = VALID_HASH_SIGNATURE_COMBINATIONS[signatureAlgorithm];
	return validHashes.map(getHashName);
}

/** Converts curve to its numeric representation */
export function fromCurveToNumber(curve: Curve): number {
	const config = CURVE_SIGNATURE_HASH_CONFIG[curve];
	if (!config) {
		throw new Error(`Unknown curve: ${curve}`);
	}
	return config.curveNumber;
}

/**
 * Converts signature algorithm to its numeric representation.
 * Number is relative to the curve (e.g., Secp256k1: ECDSA=0, Taproot=1).
 * @throws {Error} with valid algorithms if invalid combination
 */
export function fromSignatureAlgorithmToNumber(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
): number {
	const curveConfig = CURVE_SIGNATURE_HASH_CONFIG[curve];
	if (!curveConfig) {
		throw new Error(`Unknown curve: ${curve}`);
	}

	const signatureAlgorithms = curveConfig.signatureAlgorithms as Record<
		string,
		SignatureAlgorithmConfig
	>;
	const signatureConfig = signatureAlgorithms[signatureAlgorithm];
	if (!signatureConfig) {
		throw new Error(
			`Invalid signature algorithm ${signatureAlgorithm} for curve ${curve}. ` +
				`Valid algorithms: ${Object.keys(curveConfig.signatureAlgorithms).join(', ')}`,
		);
	}

	return signatureConfig.signatureAlgorithmNumber;
}

/**
 * Converts hash to its numeric representation.
 * Number is relative to curve+signature (e.g., Secp256k1+ECDSA: KECCAK256=0, SHA256=1).
 * @throws {Error} with valid hashes if invalid combination
 */
export function fromHashToNumber(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
): number {
	const curveConfig = CURVE_SIGNATURE_HASH_CONFIG[curve];
	if (!curveConfig) {
		throw new Error(`Unknown curve: ${curve}`);
	}

	const signatureAlgorithms = curveConfig.signatureAlgorithms as Record<
		string,
		SignatureAlgorithmConfig
	>;
	const signatureConfig = signatureAlgorithms[signatureAlgorithm];
	if (!signatureConfig) {
		throw new Error(
			`Invalid signature algorithm ${signatureAlgorithm} for curve ${curve}. ` +
				`Valid algorithms: ${Object.keys(curveConfig.signatureAlgorithms).join(', ')}`,
		);
	}

	const hashes = signatureConfig.hashes as Record<string, number>;
	const hashNumber = hashes[hash];
	if (hashNumber === undefined) {
		throw new Error(
			`Invalid hash ${hash} for ${signatureAlgorithm} on ${curve}. ` +
				`Valid hashes: ${Object.keys(signatureConfig.hashes).join(', ')}`,
		);
	}

	return hashNumber;
}

/** Converts curve and signature algorithm to their numeric representations */
export function fromCurveAndSignatureAlgorithmToNumbers(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
): {
	curveNumber: number;
	signatureAlgorithmNumber: number;
} {
	const curveNumber = fromCurveToNumber(curve);
	const signatureAlgorithmNumber = fromSignatureAlgorithmToNumber(curve, signatureAlgorithm);

	return {
		curveNumber,
		signatureAlgorithmNumber,
	};
}

/** Converts curve, signature algorithm, and hash to their numeric representations */
export function fromCurveAndSignatureAlgorithmAndHashToNumbers(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
): {
	curveNumber: number;
	signatureAlgorithmNumber: number;
	hashNumber: number;
} {
	const curveNumber = fromCurveToNumber(curve);
	const signatureAlgorithmNumber = fromSignatureAlgorithmToNumber(curve, signatureAlgorithm);
	const hashNumber = fromHashToNumber(curve, signatureAlgorithm, hash);

	return {
		curveNumber,
		signatureAlgorithmNumber,
		hashNumber,
	};
}

/** Type guard: is signature algorithm valid for curve? */
export function isValidSignatureAlgorithmForCurve(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
): boolean {
	const curveConfig = CURVE_SIGNATURE_HASH_CONFIG[curve];
	if (!curveConfig) return false;
	return signatureAlgorithm in curveConfig.signatureAlgorithms;
}

/** Type guard: is hash valid for curve+signature algorithm? */
export function isValidHashForCurveAndSignature(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
): boolean {
	const curveConfig = CURVE_SIGNATURE_HASH_CONFIG[curve];
	if (!curveConfig) return false;

	const signatureAlgorithms = curveConfig.signatureAlgorithms as Record<
		string,
		SignatureAlgorithmConfig
	>;
	const signatureConfig = signatureAlgorithms[signatureAlgorithm];
	if (!signatureConfig) return false;

	const hashes = signatureConfig.hashes as Record<string, number>;
	return hash in hashes;
}

/** Returns all valid signature algorithms for a curve */
export function getValidSignatureAlgorithmsForCurve(curve: Curve): SignatureAlgorithm[] {
	const curveConfig = CURVE_SIGNATURE_HASH_CONFIG[curve];
	if (!curveConfig) return [];
	return Object.keys(curveConfig.signatureAlgorithms) as SignatureAlgorithm[];
}

/** Returns all valid hashes for a curve and signature algorithm */
export function getValidHashesForCurveAndSignature(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
): Hash[] {
	const curveConfig = CURVE_SIGNATURE_HASH_CONFIG[curve];
	if (!curveConfig) return [];

	const signatureAlgorithms = curveConfig.signatureAlgorithms as Record<
		string,
		SignatureAlgorithmConfig
	>;
	const signatureConfig = signatureAlgorithms[signatureAlgorithm];
	if (!signatureConfig) return [];

	return Object.keys(signatureConfig.hashes) as Hash[];
}

/**
 * Converts curve number to its Curve enum (direct conversion).
 * @throws {Error} if curve number is unknown
 */
export function fromNumberToCurve(curveNumber: number): Curve {
	for (const [curve, config] of Object.entries(CURVE_SIGNATURE_HASH_CONFIG)) {
		if (config.curveNumber === curveNumber) {
			return curve as Curve;
		}
	}
	throw new Error(`Unknown curve number: ${curveNumber}`);
}

/**
 * Converts absolute signature algorithm number to its SignatureAlgorithm enum (direct conversion).
 * Uses global numbering: ECDSASecp256k1=0, Taproot=1, ECDSASecp256r1=2, EdDSA=3, SchnorrkelSubstrate=4
 * @throws {Error} if number is unknown
 */
export function fromAbsoluteNumberToSignatureAlgorithm(absoluteNumber: number): SignatureAlgorithm {
	for (const [signatureAlgorithm, number] of Object.entries(SIGNATURE_ALGORITHM_ABSOLUTE_NUMBERS)) {
		if (number === absoluteNumber) {
			return signatureAlgorithm as SignatureAlgorithm;
		}
	}
	throw new Error(`Unknown absolute signature algorithm number: ${absoluteNumber}`);
}

/**
 * Converts SignatureAlgorithm enum to its absolute number (direct conversion).
 * Uses global numbering: ECDSASecp256k1=0, Taproot=1, ECDSASecp256r1=2, EdDSA=3, SchnorrkelSubstrate=4
 */
export function fromSignatureAlgorithmToAbsoluteNumber(
	signatureAlgorithm: SignatureAlgorithm,
): number {
	const absoluteNumber = SIGNATURE_ALGORITHM_ABSOLUTE_NUMBERS[signatureAlgorithm];
	if (absoluteNumber === undefined) {
		throw new Error(`Unknown signature algorithm: ${signatureAlgorithm}`);
	}
	return absoluteNumber;
}

/**
 * Converts absolute hash number to its Hash enum (direct conversion).
 * Uses global numbering: KECCAK256=0, SHA256=1, DoubleSHA256=2, SHA512=3, Merlin=4
 * @throws {Error} if number is unknown
 */
export function fromAbsoluteNumberToHash(absoluteNumber: number): Hash {
	for (const [hash, number] of Object.entries(HASH_ABSOLUTE_NUMBERS)) {
		if (number === absoluteNumber) {
			return hash as Hash;
		}
	}
	throw new Error(`Unknown absolute hash number: ${absoluteNumber}`);
}

/**
 * Converts Hash enum to its absolute number (direct conversion).
 * Uses global numbering: KECCAK256=0, SHA256=1, DoubleSHA256=2, SHA512=3, Merlin=4
 */
export function fromHashToAbsoluteNumber(hash: Hash): number {
	const absoluteNumber = HASH_ABSOLUTE_NUMBERS[hash];
	if (absoluteNumber === undefined) {
		throw new Error(`Unknown hash: ${hash}`);
	}
	return absoluteNumber;
}

/**
 * Converts signature algorithm number to its SignatureAlgorithm enum.
 * Number is relative to the curve (e.g., Secp256k1: 0=ECDSA, 1=Taproot).
 * @throws {Error} if signature algorithm number is unknown for the curve
 */
export function fromNumberToSignatureAlgorithm(
	curve: Curve,
	signatureAlgorithmNumber: number,
): SignatureAlgorithm {
	const curveConfig = CURVE_SIGNATURE_HASH_CONFIG[curve];
	if (!curveConfig) {
		throw new Error(`Unknown curve: ${curve}`);
	}

	const signatureAlgorithms = curveConfig.signatureAlgorithms as Record<
		string,
		SignatureAlgorithmConfig
	>;

	for (const [signatureAlgorithm, config] of Object.entries(signatureAlgorithms)) {
		if (config.signatureAlgorithmNumber === signatureAlgorithmNumber) {
			return signatureAlgorithm as SignatureAlgorithm;
		}
	}

	throw new Error(
		`Unknown signature algorithm number ${signatureAlgorithmNumber} for curve ${curve}`,
	);
}

/**
 * Converts hash number to its Hash enum.
 * Number is relative to curve+signature (e.g., Secp256k1+ECDSA: 0=KECCAK256, 1=SHA256).
 * @throws {Error} if hash number is unknown for the curve+signature algorithm combination
 */
export function fromNumberToHash(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hashNumber: number,
): Hash {
	const curveConfig = CURVE_SIGNATURE_HASH_CONFIG[curve];
	if (!curveConfig) {
		throw new Error(`Unknown curve: ${curve}`);
	}

	const signatureAlgorithms = curveConfig.signatureAlgorithms as Record<
		string,
		SignatureAlgorithmConfig
	>;
	const signatureConfig = signatureAlgorithms[signatureAlgorithm];
	if (!signatureConfig) {
		throw new Error(`Invalid signature algorithm ${signatureAlgorithm} for curve ${curve}`);
	}

	const hashes = signatureConfig.hashes as Record<string, number>;
	for (const [hash, number] of Object.entries(hashes)) {
		if (number === hashNumber) {
			return hash as Hash;
		}
	}

	throw new Error(`Unknown hash number ${hashNumber} for ${signatureAlgorithm} on ${curve}`);
}

/**
 * Converts curve and signature algorithm numbers to their enum representations.
 * @throws {Error} if numbers are unknown
 */
export function fromNumbersToCurveAndSignatureAlgorithm(
	curveNumber: number,
	signatureAlgorithmNumber: number,
): {
	curve: Curve;
	signatureAlgorithm: SignatureAlgorithm;
} {
	const curve = fromNumberToCurve(curveNumber);
	const signatureAlgorithm = fromNumberToSignatureAlgorithm(curve, signatureAlgorithmNumber);

	return {
		curve,
		signatureAlgorithm,
	};
}

/**
 * Converts curve, signature algorithm, and hash numbers to their enum representations.
 * @throws {Error} if numbers are unknown
 */
export function fromNumbersToCurveAndSignatureAlgorithmAndHash(
	curveNumber: number,
	signatureAlgorithmNumber: number,
	hashNumber: number,
): {
	curve: Curve;
	signatureAlgorithm: SignatureAlgorithm;
	hash: Hash;
} {
	const curve = fromNumberToCurve(curveNumber);
	const signatureAlgorithm = fromNumberToSignatureAlgorithm(curve, signatureAlgorithmNumber);
	const hash = fromNumberToHash(curve, signatureAlgorithm, hashNumber);

	return {
		curve,
		signatureAlgorithm,
		hash,
	};
}
