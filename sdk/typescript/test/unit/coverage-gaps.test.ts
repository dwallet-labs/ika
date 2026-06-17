// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

// Chain-agnostic coverage for spots the testnet e2e can't exercise
// efficiently: validation failure paths, error class hierarchy, IkaClient
// configuration setters and cache predicates.

import type { ClientWithCoreApi } from '@mysten/sui/client';
import { describe, expect, it } from 'vitest';

import {
	CacheError,
	createValidatedSigningParams,
	Curve,
	fromAbsoluteNumberToHash,
	fromAbsoluteNumberToSignatureAlgorithm,
	fromCurveAndSignatureAlgorithmAndHashToNumbers,
	fromCurveToNumber,
	fromHashToAbsoluteNumber,
	fromHashToNumber,
	fromNumbersToCurveAndSignatureAlgorithm,
	fromNumbersToCurveAndSignatureAlgorithmAndHash,
	fromNumberToCurve,
	fromNumberToHash,
	fromNumberToSignatureAlgorithm,
	fromSignatureAlgorithmToAbsoluteNumber,
	fromSignatureAlgorithmToNumber,
	getCurveName,
	getHashName,
	getNetworkConfig,
	getSignatureAlgorithmName,
	getValidHashesForCurveAndSignature,
	getValidHashesForSignatureAlgorithm,
	getValidSignatureAlgorithmsForCurve,
	Hash,
	IkaClient,
	IkaClientError,
	InvalidObjectError,
	isValidHashForCurveAndSignature,
	isValidHashForSignature,
	isValidSignatureAlgorithmForCurve,
	NetworkError,
	ObjectNotFoundError,
	SignatureAlgorithm,
	validateCurveSignatureAlgorithm,
	validateHashSignatureCombination,
} from '../../src';

// =============================================================================
// validateHashSignatureCombination — every sigAlgo × every wrong hash
// =============================================================================

describe('validateHashSignatureCombination', () => {
	const positives: Array<[Hash, SignatureAlgorithm]> = [
		[Hash.KECCAK256, SignatureAlgorithm.ECDSASecp256k1],
		[Hash.SHA256, SignatureAlgorithm.ECDSASecp256k1],
		[Hash.DoubleSHA256, SignatureAlgorithm.ECDSASecp256k1],
		[Hash.SHA256, SignatureAlgorithm.Taproot],
		[Hash.SHA256, SignatureAlgorithm.ECDSASecp256r1],
		[Hash.SHA512, SignatureAlgorithm.EdDSA],
		[Hash.Merlin, SignatureAlgorithm.SchnorrkelSubstrate],
	];

	it.each(positives)('accepts %s for %s', (hash, sigAlgo) => {
		expect(() => validateHashSignatureCombination(hash, sigAlgo)).not.toThrow();
	});

	const negatives: Array<[Hash, SignatureAlgorithm]> = [
		[Hash.SHA512, SignatureAlgorithm.ECDSASecp256k1],
		[Hash.Merlin, SignatureAlgorithm.ECDSASecp256k1],
		[Hash.DoubleSHA256, SignatureAlgorithm.Taproot],
		[Hash.KECCAK256, SignatureAlgorithm.Taproot],
		[Hash.KECCAK256, SignatureAlgorithm.ECDSASecp256r1],
		[Hash.SHA256, SignatureAlgorithm.EdDSA],
		[Hash.SHA256, SignatureAlgorithm.SchnorrkelSubstrate],
	];

	it.each(negatives)('rejects %s for %s', (hash, sigAlgo) => {
		expect(() => validateHashSignatureCombination(hash, sigAlgo)).toThrow(/Invalid hash/);
	});
});

// =============================================================================
// validateCurveSignatureAlgorithm — wrong curve for each sigAlgo
// =============================================================================

describe('validateCurveSignatureAlgorithm', () => {
	const positives: Array<[Curve, SignatureAlgorithm]> = [
		[Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1],
		[Curve.SECP256K1, SignatureAlgorithm.Taproot],
		[Curve.SECP256R1, SignatureAlgorithm.ECDSASecp256r1],
		[Curve.ED25519, SignatureAlgorithm.EdDSA],
		[Curve.RISTRETTO, SignatureAlgorithm.SchnorrkelSubstrate],
	];

	it.each(positives)('accepts %s with %s', (curve, sigAlgo) => {
		expect(() => validateCurveSignatureAlgorithm(curve, sigAlgo)).not.toThrow();
	});

	const negatives: Array<[Curve, SignatureAlgorithm]> = [
		[Curve.SECP256R1, SignatureAlgorithm.ECDSASecp256k1],
		[Curve.ED25519, SignatureAlgorithm.Taproot],
		[Curve.RISTRETTO, SignatureAlgorithm.EdDSA],
		[Curve.SECP256K1, SignatureAlgorithm.SchnorrkelSubstrate],
		[Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256r1],
	];

	it.each(negatives)('rejects %s with %s', (curve, sigAlgo) => {
		expect(() => validateCurveSignatureAlgorithm(curve, sigAlgo)).toThrow(/Invalid curve/);
	});
});

// =============================================================================
// isValid* type-guard family
// =============================================================================

describe('isValid* type guards', () => {
	it('isValidHashForSignature', () => {
		expect(isValidHashForSignature(Hash.SHA256, SignatureAlgorithm.Taproot)).toBe(true);
		expect(isValidHashForSignature(Hash.KECCAK256, SignatureAlgorithm.Taproot)).toBe(false);
	});

	it('isValidSignatureAlgorithmForCurve', () => {
		expect(isValidSignatureAlgorithmForCurve(Curve.SECP256K1, SignatureAlgorithm.Taproot)).toBe(
			true,
		);
		expect(isValidSignatureAlgorithmForCurve(Curve.ED25519, SignatureAlgorithm.Taproot)).toBe(
			false,
		);
	});

	it('isValidHashForCurveAndSignature', () => {
		expect(
			isValidHashForCurveAndSignature(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.KECCAK256,
			),
		).toBe(true);
		expect(
			isValidHashForCurveAndSignature(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.SHA512,
			),
		).toBe(false);
		expect(
			isValidHashForCurveAndSignature(
				Curve.ED25519,
				SignatureAlgorithm.ECDSASecp256k1, // sig invalid for curve
				Hash.KECCAK256,
			),
		).toBe(false);
	});

	it('createValidatedSigningParams round-trips and rejects bad combos at runtime', () => {
		const ok = createValidatedSigningParams(Hash.SHA256, SignatureAlgorithm.Taproot);
		expect(ok).toEqual({ hashScheme: Hash.SHA256, signatureAlgorithm: SignatureAlgorithm.Taproot });
		expect(() =>
			// @ts-expect-error — deliberately invalid combo
			createValidatedSigningParams(Hash.KECCAK256, SignatureAlgorithm.EdDSA),
		).toThrow(/Invalid hash/);
	});
});

// =============================================================================
// getValid*ForCurve(AndSignature) listings
// =============================================================================

describe('getValid* listings', () => {
	it('getValidHashesForSignatureAlgorithm returns the three ECDSAk1 hashes', () => {
		const hashes = getValidHashesForSignatureAlgorithm(SignatureAlgorithm.ECDSASecp256k1);
		expect(hashes.sort()).toEqual(['DoubleSHA256', 'KECCAK256 (SHA3)', 'SHA256'].sort());
	});

	it('getValidSignatureAlgorithmsForCurve returns both SECP256K1 algorithms', () => {
		const algos = getValidSignatureAlgorithmsForCurve(Curve.SECP256K1).sort();
		expect(algos).toEqual([SignatureAlgorithm.ECDSASecp256k1, SignatureAlgorithm.Taproot].sort());
	});

	it('getValidSignatureAlgorithmsForCurve returns single algos for other curves', () => {
		expect(getValidSignatureAlgorithmsForCurve(Curve.ED25519)).toEqual([SignatureAlgorithm.EdDSA]);
		expect(getValidSignatureAlgorithmsForCurve(Curve.RISTRETTO)).toEqual([
			SignatureAlgorithm.SchnorrkelSubstrate,
		]);
		expect(getValidSignatureAlgorithmsForCurve(Curve.SECP256R1)).toEqual([
			SignatureAlgorithm.ECDSASecp256r1,
		]);
	});

	it('getValidHashesForCurveAndSignature', () => {
		expect(getValidHashesForCurveAndSignature(Curve.SECP256K1, SignatureAlgorithm.Taproot)).toEqual(
			[Hash.SHA256],
		);
		expect(getValidHashesForCurveAndSignature(Curve.ED25519, SignatureAlgorithm.EdDSA)).toEqual([
			Hash.SHA512,
		]);
	});
});

// =============================================================================
// Number conversions — round-trip every curve / sig / hash
// =============================================================================

describe('enum <-> number conversions', () => {
	const allCurves = [Curve.SECP256K1, Curve.SECP256R1, Curve.ED25519, Curve.RISTRETTO];

	it('curve round-trip', () => {
		for (const curve of allCurves) {
			expect(fromNumberToCurve(fromCurveToNumber(curve))).toBe(curve);
		}
	});

	it('fromNumberToCurve throws on unknown number', () => {
		expect(() => fromNumberToCurve(99)).toThrow(/Unknown curve number/);
	});

	it('signature algorithm absolute numbers round-trip', () => {
		const allSigs = [
			SignatureAlgorithm.ECDSASecp256k1,
			SignatureAlgorithm.Taproot,
			SignatureAlgorithm.ECDSASecp256r1,
			SignatureAlgorithm.EdDSA,
			SignatureAlgorithm.SchnorrkelSubstrate,
		];
		for (const sig of allSigs) {
			expect(
				fromAbsoluteNumberToSignatureAlgorithm(fromSignatureAlgorithmToAbsoluteNumber(sig)),
			).toBe(sig);
		}
	});

	it('hash absolute numbers round-trip', () => {
		const allHashes = [Hash.KECCAK256, Hash.SHA256, Hash.DoubleSHA256, Hash.SHA512, Hash.Merlin];
		for (const hash of allHashes) {
			expect(fromAbsoluteNumberToHash(fromHashToAbsoluteNumber(hash))).toBe(hash);
		}
	});

	it('curve-relative signature/hash conversions for SECP256K1+ECDSA+KECCAK', () => {
		const { curveNumber, signatureAlgorithmNumber, hashNumber } =
			fromCurveAndSignatureAlgorithmAndHashToNumbers(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.KECCAK256,
			);
		expect(curveNumber).toBe(0);
		expect(signatureAlgorithmNumber).toBe(0);
		expect(hashNumber).toBe(0);

		const round = fromNumbersToCurveAndSignatureAlgorithmAndHash(
			curveNumber,
			signatureAlgorithmNumber,
			hashNumber,
		);
		expect(round.curve).toBe(Curve.SECP256K1);
		expect(round.signatureAlgorithm).toBe(SignatureAlgorithm.ECDSASecp256k1);
		expect(round.hash).toBe(Hash.KECCAK256);
	});

	it('fromNumbersToCurveAndSignatureAlgorithm', () => {
		const r = fromNumbersToCurveAndSignatureAlgorithm(0, 1);
		expect(r.curve).toBe(Curve.SECP256K1);
		expect(r.signatureAlgorithm).toBe(SignatureAlgorithm.Taproot);
	});

	it('fromSignatureAlgorithmToNumber rejects invalid combo', () => {
		expect(() => fromSignatureAlgorithmToNumber(Curve.ED25519, SignatureAlgorithm.Taproot)).toThrow(
			/Invalid signature algorithm/,
		);
	});

	it('fromHashToNumber rejects invalid hash for curve+sig', () => {
		expect(() =>
			fromHashToNumber(Curve.SECP256K1, SignatureAlgorithm.Taproot, Hash.KECCAK256),
		).toThrow(/Invalid hash/);
	});

	it('fromNumberToSignatureAlgorithm and fromNumberToHash reject unknown numbers', () => {
		expect(() => fromNumberToSignatureAlgorithm(Curve.SECP256K1, 99)).toThrow();
		expect(() =>
			fromNumberToHash(Curve.SECP256K1, SignatureAlgorithm.ECDSASecp256k1, 99),
		).toThrow();
	});
});

// =============================================================================
// Name helpers
// =============================================================================

describe('name helpers', () => {
	it('hash names', () => {
		expect(getHashName(Hash.KECCAK256)).toMatch(/KECCAK/);
		expect(getHashName(Hash.SHA256)).toBe('SHA256');
		expect(getHashName(Hash.DoubleSHA256)).toBe('DoubleSHA256');
		expect(getHashName(Hash.SHA512)).toBe('SHA512');
		expect(getHashName(Hash.Merlin)).toBe('Merlin');
	});

	it('sig names', () => {
		expect(getSignatureAlgorithmName(SignatureAlgorithm.ECDSASecp256k1)).toBe('ECDSASecp256k1');
		expect(getSignatureAlgorithmName(SignatureAlgorithm.Taproot)).toBe('Taproot');
		expect(getSignatureAlgorithmName(SignatureAlgorithm.ECDSASecp256r1)).toBe('ECDSASecp256r1');
		expect(getSignatureAlgorithmName(SignatureAlgorithm.EdDSA)).toBe('EdDSA');
		expect(getSignatureAlgorithmName(SignatureAlgorithm.SchnorrkelSubstrate)).toMatch(/Schnorrkel/);
	});

	it('curve names', () => {
		expect(getCurveName(Curve.SECP256K1)).toBe('secp256k1');
		expect(getCurveName(Curve.SECP256R1)).toBe('secp256r1');
		expect(getCurveName(Curve.ED25519)).toBe('Ed25519');
		expect(getCurveName(Curve.RISTRETTO)).toBe('Ristretto');
	});
});

// =============================================================================
// Error class hierarchy
// =============================================================================

describe('error classes', () => {
	it('IkaClientError preserves message and cause', () => {
		const cause = new Error('root');
		const err = new IkaClientError('boom', cause);
		expect(err).toBeInstanceOf(Error);
		expect(err.name).toBe('IkaClientError');
		expect(err.message).toBe('boom');
		expect(err.cause).toBe(cause);
	});

	it('ObjectNotFoundError formats with and without id', () => {
		const withId = new ObjectNotFoundError('DWallet', '0xabc');
		expect(withId).toBeInstanceOf(IkaClientError);
		expect(withId.name).toBe('ObjectNotFoundError');
		expect(withId.message).toBe('DWallet object with ID 0xabc not found');

		const noId = new ObjectNotFoundError('Presign');
		expect(noId.message).toBe('Presign object not found');
	});

	it('InvalidObjectError formats with and without id', () => {
		const e = new InvalidObjectError('DWallet', '0xabc');
		expect(e).toBeInstanceOf(IkaClientError);
		expect(e.message).toBe('Invalid DWallet object (ID: 0xabc): Expected structure not found');

		const noId = new InvalidObjectError('Sign');
		expect(noId.message).toBe('Invalid Sign object: Expected structure not found');
	});

	it('NetworkError and CacheError', () => {
		const ne = new NetworkError('rpc down');
		expect(ne).toBeInstanceOf(IkaClientError);
		expect(ne.name).toBe('NetworkError');
		expect(ne.message).toBe('Network error: rpc down');

		const ce = new CacheError('stale');
		expect(ce).toBeInstanceOf(IkaClientError);
		expect(ce.name).toBe('CacheError');
		expect(ce.message).toBe('Cache error: stale');
	});
});

// =============================================================================
// IkaClient — chain-agnostic surface (no RPC calls)
// =============================================================================

describe('IkaClient (offline)', () => {
	function makeClient() {
		// suiClient is never called for the methods we test below
		return new IkaClient({
			suiClient: {} as unknown as ClientWithCoreApi,
			config: getNetworkConfig('testnet'),
			cache: true,
		});
	}

	it('default encryption-key options auto-detect', () => {
		const c = makeClient();
		expect(c.getEncryptionKeyOptions()).toEqual({ autoDetect: true });
	});

	it('setEncryptionKeyOptions / setEncryptionKeyID round-trip', () => {
		const c = makeClient();
		c.setEncryptionKeyOptions({ autoDetect: false, encryptionKeyID: '0x1' });
		expect(c.getEncryptionKeyOptions()).toEqual({ autoDetect: false, encryptionKeyID: '0x1' });

		c.setEncryptionKeyID('0x2');
		expect(c.getEncryptionKeyOptions().encryptionKeyID).toBe('0x2');
		// autoDetect should be preserved
		expect(c.getEncryptionKeyOptions().autoDetect).toBe(false);
	});

	it('encryption-key options getter returns a copy (mutations don’t leak)', () => {
		const c = makeClient();
		const opts = c.getEncryptionKeyOptions();
		opts.encryptionKeyID = '0xZZZ';
		expect(c.getEncryptionKeyOptions().encryptionKeyID).toBeUndefined();
	});

	it('cache predicates start empty', () => {
		const c = makeClient();
		expect(c.isProtocolPublicParametersCached('0xabc', Curve.SECP256K1)).toBe(false);
		expect(c.getCachedProtocolPublicParameters('0xabc', Curve.SECP256K1)).toBeUndefined();
	});

	it('invalidate* methods are callable on a fresh client', () => {
		const c = makeClient();
		expect(() => c.invalidateCache()).not.toThrow();
		expect(() => c.invalidateObjectCache()).not.toThrow();
		expect(() => c.invalidateEncryptionKeyCache()).not.toThrow();
		expect(() => c.invalidateProtocolPublicParametersCache()).not.toThrow();
		expect(() => c.invalidateProtocolPublicParametersCache('0xabc')).not.toThrow();
		expect(() => c.invalidateProtocolPublicParametersCache('0xabc', Curve.SECP256K1)).not.toThrow();
	});

	it('exposes ikaConfig from constructor input', () => {
		const config = getNetworkConfig('mainnet');
		const c = new IkaClient({
			suiClient: {} as unknown as ClientWithCoreApi,
			config,
			cache: false,
		});
		expect(c.ikaConfig.packages.ikaPackage).toBe(config.packages.ikaPackage);
		expect(c.ikaConfig.objects.ikaDWalletCoordinator.objectID).toBe(
			config.objects.ikaDWalletCoordinator.objectID,
		);
	});
});

// =============================================================================
// getNetworkConfig sanity
// =============================================================================

describe('getNetworkConfig', () => {
	it('testnet config has both packages and shared objects', () => {
		const cfg = getNetworkConfig('testnet');
		expect(cfg.packages.ikaPackage).toMatch(/^0x[0-9a-f]+$/);
		expect(cfg.objects.ikaDWalletCoordinator.objectID).toMatch(/^0x[0-9a-f]+$/);
		expect(cfg.objects.ikaSystemObject.initialSharedVersion).toBeGreaterThan(0);
	});

	it('mainnet config differs from testnet', () => {
		const m = getNetworkConfig('mainnet');
		const t = getNetworkConfig('testnet');
		expect(m.packages.ikaPackage).not.toBe(t.packages.ikaPackage);
		expect(m.objects.ikaDWalletCoordinator.objectID).not.toBe(
			t.objects.ikaDWalletCoordinator.objectID,
		);
	});
});
