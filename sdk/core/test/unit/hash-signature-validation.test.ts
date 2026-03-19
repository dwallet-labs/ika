// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import {
	Curve,
	fromAbsoluteNumberToHash,
	fromAbsoluteNumberToSignatureAlgorithm,
	fromCurveAndSignatureAlgorithmAndHashToNumbers,
	fromCurveToNumber,
	fromHashToAbsoluteNumber,
	fromHashToNumber,
	fromNumberToCurve,
	fromNumberToHash,
	fromNumberToSignatureAlgorithm,
	fromSignatureAlgorithmToAbsoluteNumber,
	fromSignatureAlgorithmToNumber,
	getValidHashesForCurveAndSignature,
	getValidSignatureAlgorithmsForCurve,
	Hash,
	isValidHashForCurveAndSignature,
	isValidSignatureAlgorithmForCurve,
	SignatureAlgorithm,
	validateCurveSignatureAlgorithm,
	validateHashSignatureCombination,
} from '../../src';

describe('Curve numbering', () => {
	it('should round-trip all curves through number conversion', () => {
		for (const curve of Object.values(Curve)) {
			const num = fromCurveToNumber(curve);
			expect(fromNumberToCurve(num)).toBe(curve);
		}
	});

	it('should assign stable numbers', () => {
		expect(fromCurveToNumber(Curve.SECP256K1)).toBe(0);
		expect(fromCurveToNumber(Curve.SECP256R1)).toBe(1);
		expect(fromCurveToNumber(Curve.ED25519)).toBe(2);
		expect(fromCurveToNumber(Curve.RISTRETTO)).toBe(3);
	});

	it('should reject unknown curve numbers', () => {
		expect(() => fromNumberToCurve(99)).toThrow();
	});
});

describe('SignatureAlgorithm numbering', () => {
	it('should round-trip absolute numbers', () => {
		for (const sa of Object.values(SignatureAlgorithm)) {
			const num = fromSignatureAlgorithmToAbsoluteNumber(sa);
			expect(fromAbsoluteNumberToSignatureAlgorithm(num)).toBe(sa);
		}
	});

	it('should round-trip relative numbers per curve', () => {
		for (const curve of Object.values(Curve)) {
			for (const sa of getValidSignatureAlgorithmsForCurve(curve)) {
				const num = fromSignatureAlgorithmToNumber(curve, sa);
				expect(fromNumberToSignatureAlgorithm(curve, num)).toBe(sa);
			}
		}
	});
});

describe('Hash numbering', () => {
	it('should round-trip absolute numbers', () => {
		for (const h of Object.values(Hash)) {
			const num = fromHashToAbsoluteNumber(h);
			expect(fromAbsoluteNumberToHash(num)).toBe(h);
		}
	});

	it('should round-trip relative numbers per curve+signature', () => {
		for (const curve of Object.values(Curve)) {
			for (const sa of getValidSignatureAlgorithmsForCurve(curve)) {
				for (const h of getValidHashesForCurveAndSignature(curve, sa)) {
					const num = fromHashToNumber(curve, sa, h);
					expect(fromNumberToHash(curve, sa, num)).toBe(h);
				}
			}
		}
	});
});

describe('Curve-SignatureAlgorithm validation', () => {
	it('should accept valid combinations', () => {
		expect(() => validateCurveSignatureAlgorithm(Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1)).not.toThrow();
		expect(() => validateCurveSignatureAlgorithm(Curve.SECP256K1, SignatureAlgorithm.Taproot)).not.toThrow();
		expect(() => validateCurveSignatureAlgorithm(Curve.ED25519, SignatureAlgorithm.EdDSA)).not.toThrow();
	});

	it('should reject invalid combinations', () => {
		expect(() => validateCurveSignatureAlgorithm(Curve.SECP256K1, SignatureAlgorithm.EdDSA)).toThrow();
		expect(() => validateCurveSignatureAlgorithm(Curve.ED25519, SignatureAlgorithm.ECDSASecp256k1)).toThrow();
	});

	it('isValidSignatureAlgorithmForCurve should match', () => {
		expect(isValidSignatureAlgorithmForCurve(Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1)).toBe(true);
		expect(isValidSignatureAlgorithmForCurve(Curve.SECP256K1, SignatureAlgorithm.EdDSA)).toBe(false);
	});
});

describe('Hash-SignatureAlgorithm validation', () => {
	it('should accept valid combinations', () => {
		expect(() => validateHashSignatureCombination(Hash.KECCAK256, SignatureAlgorithm.ECDSASecp256k1)).not.toThrow();
		expect(() => validateHashSignatureCombination(Hash.SHA512, SignatureAlgorithm.EdDSA)).not.toThrow();
		expect(() => validateHashSignatureCombination(Hash.Merlin, SignatureAlgorithm.SchnorrkelSubstrate)).not.toThrow();
	});

	it('should reject invalid combinations', () => {
		expect(() => validateHashSignatureCombination(Hash.SHA512, SignatureAlgorithm.ECDSASecp256k1)).toThrow();
		expect(() => validateHashSignatureCombination(Hash.KECCAK256, SignatureAlgorithm.EdDSA)).toThrow();
	});

	it('isValidHashForCurveAndSignature should match', () => {
		expect(isValidHashForCurveAndSignature(Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1, Hash.KECCAK256)).toBe(true);
		expect(isValidHashForCurveAndSignature(Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1, Hash.SHA512)).toBe(false);
	});
});

describe('Full triple conversion', () => {
	it('should convert all valid triples to numbers and back', () => {
		const validTriples: [Curve, SignatureAlgorithm, Hash][] = [
			[Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1, Hash.KECCAK256],
			[Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1, Hash.SHA256],
			[Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1, Hash.DoubleSHA256],
			[Curve.SECP256K1, SignatureAlgorithm.Taproot, Hash.SHA256],
			[Curve.SECP256R1, SignatureAlgorithm.ECDSASecp256r1, Hash.SHA256],
			[Curve.ED25519, SignatureAlgorithm.EdDSA, Hash.SHA512],
			[Curve.RISTRETTO, SignatureAlgorithm.SchnorrkelSubstrate, Hash.Merlin],
		];

		for (const [curve, sa, hash] of validTriples) {
			const { curveNumber, signatureAlgorithmNumber, hashNumber } =
				fromCurveAndSignatureAlgorithmAndHashToNumbers(curve, sa, hash);

			expect(fromNumberToCurve(curveNumber)).toBe(curve);
			expect(fromNumberToSignatureAlgorithm(curve, signatureAlgorithmNumber)).toBe(sa);
			expect(fromNumberToHash(curve, sa, hashNumber)).toBe(hash);
		}
	});
});
