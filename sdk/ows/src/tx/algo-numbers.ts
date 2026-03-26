// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Curve/algorithm/hash to u32 conversion.
 *
 * These mappings are the authoritative values from the Ika SDK's
 * internal `hash-signature-validation` module. They must match the
 * Move coordinator's SupportConfig.
 *
 * The numbers are CONTEXTUAL:
 * - signatureAlgorithm numbers are per-curve
 * - hash numbers are per-curve-per-signatureAlgorithm
 */

import type { Curve, Hash, SignatureAlgorithm } from '@ika.xyz/sdk';

interface AlgoNumbers {
	signatureAlgorithmNumber: number;
	hashNumber: number;
}

/**
 * Config: curve → signatureAlgorithm → { sigNum, hashes: hash → hashNum }
 *
 * Source: ika SDK's CURVE_SIGNATURE_HASH_CONFIG
 */
const CONFIG: Record<string, Record<string, { sigNum: number; hashes: Record<string, number> }>> = {
	SECP256K1: {
		ECDSASecp256k1: { sigNum: 0, hashes: { KECCAK256: 0, SHA256: 1, DoubleSHA256: 2 } },
		Taproot: { sigNum: 1, hashes: { SHA256: 0 } },
	},
	SECP256R1: {
		ECDSASecp256r1: { sigNum: 0, hashes: { SHA256: 0 } },
	},
	ED25519: {
		EdDSA: { sigNum: 0, hashes: { SHA512: 0 } },
	},
	RISTRETTO: {
		SchnorrkelSubstrate: { sigNum: 0, hashes: { Merlin: 0 } },
	},
};

export function fromCurveAndSignatureAlgorithmAndHashToNumbers(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
): AlgoNumbers {
	const curveConfig = CONFIG[curve];
	if (!curveConfig) throw new Error(`Unsupported curve: ${curve}`);

	const algoConfig = curveConfig[signatureAlgorithm];
	if (!algoConfig) throw new Error(`Unsupported algorithm ${signatureAlgorithm} for curve ${curve}`);

	const hashNumber = algoConfig.hashes[hash];
	if (hashNumber === undefined) throw new Error(`Unsupported hash ${hash} for ${curve}/${signatureAlgorithm}`);

	return {
		signatureAlgorithmNumber: algoConfig.sigNum,
		hashNumber,
	};
}
