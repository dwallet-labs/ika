// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/**
 * Convert Ika SDK string enums to the u32 numbers expected by Move contracts.
 *
 * These mappings mirror the internal conversion in the Ika SDK's
 * `hash-signature-validation.ts` module.
 */

import type { Hash, SignatureAlgorithm } from '@ika.xyz/sdk';

const SIGNATURE_ALGORITHM_NUMBERS: Record<string, number> = {
	ECDSASecp256k1: 0,
	ECDSASecp256r1: 1,
	Schnorr: 2,
	EdDSA: 0,
};

const HASH_NUMBERS: Record<string, number> = {
	SHA256: 0,
	KECCAK256: 1,
	DoubleSHA256: 2,
	SHA512: 0,
};

export function signatureAlgorithmToNumber(algo: SignatureAlgorithm): number {
	const num = SIGNATURE_ALGORITHM_NUMBERS[algo];
	if (num === undefined) {
		throw new Error(`Unknown signature algorithm: ${algo}`);
	}
	return num;
}

export function hashToNumber(hash: Hash): number {
	const num = HASH_NUMBERS[hash];
	if (num === undefined) {
		throw new Error(`Unknown hash: ${hash}`);
	}
	return num;
}
