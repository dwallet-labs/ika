// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import * as core from '../../src';

describe('Core package exports', () => {
	it('should export cryptography functions', () => {
		expect(typeof core.createClassGroupsKeypair).toBe('function');
		expect(typeof core.createDKGUserOutput).toBe('function');
		expect(typeof core.encryptSecretShare).toBe('function');
		expect(typeof core.prepareDKG).toBe('function');
		expect(typeof core.prepareImportedKeyVerification).toBe('function');
		expect(typeof core.createUserSignMessageWithPublicOutput).toBe('function');
		expect(typeof core.createUserSignMessageWithCentralizedOutput).toBe('function');
		expect(typeof core.verifySecpSignature).toBe('function');
		expect(typeof core.verifyUserShare).toBe('function');
		expect(typeof core.publicKeyFromDWalletOutput).toBe('function');
		expect(typeof core.publicKeyFromCentralizedDKGOutput).toBe('function');
		expect(typeof core.userAndNetworkDKGOutputMatch).toBe('function');
		expect(typeof core.parseSignatureFromSignOutput).toBe('function');
		expect(typeof core.sessionIdentifierDigest).toBe('function');
		expect(typeof core.createRandomSessionIdentifier).toBe('function');
		expect(typeof core.networkDkgPublicOutputToProtocolPublicParameters).toBe('function');
		expect(typeof core.reconfigurationPublicOutputToProtocolPublicParameters).toBe('function');
	});

	it('should export Ed25519Keypair', () => {
		expect(typeof core.Ed25519Keypair).toBe('function');
		expect(typeof core.Ed25519Keypair.fromSeed).toBe('function');
		expect(typeof core.Ed25519Keypair.fromSecretKey).toBe('function');
		expect(typeof core.Ed25519Keypair.deriveKeypairFromSeed).toBe('function');
	});

	it('should export UserShareEncryptionKeys', () => {
		expect(typeof core.UserShareEncryptionKeys).toBe('function');
		expect(typeof core.UserShareEncryptionKeys.fromRootSeedKey).toBe('function');
		expect(typeof core.UserShareEncryptionKeys.fromRootSeedKeyLegacyHash).toBe('function');
		expect(typeof core.UserShareEncryptionKeys.fromShareEncryptionKeysBytes).toBe('function');
		expect(typeof core.UserShareEncryptionKeys.fromKeyMaterial).toBe('function');
	});

	it('should export type enums', () => {
		expect(core.Curve.SECP256K1).toBe('SECP256K1');
		expect(core.Curve.SECP256R1).toBe('SECP256R1');
		expect(core.Curve.ED25519).toBe('ED25519');
		expect(core.Curve.RISTRETTO).toBe('RISTRETTO');

		expect(core.Hash.KECCAK256).toBe('KECCAK256');
		expect(core.Hash.SHA256).toBe('SHA256');
		expect(core.Hash.SHA512).toBe('SHA512');

		expect(core.SignatureAlgorithm.ECDSASecp256k1).toBe('ECDSASecp256k1');
		expect(core.SignatureAlgorithm.EdDSA).toBe('EdDSA');
		expect(core.SignatureAlgorithm.Taproot).toBe('Taproot');

		expect(core.DWalletKind.ZeroTrust).toBe('zero-trust');
		expect(core.DWalletKind.ImportedKey).toBe('imported-key');
	});

	it('should export hash-signature-validation functions', () => {
		expect(typeof core.validateCurveSignatureAlgorithm).toBe('function');
		expect(typeof core.validateHashSignatureCombination).toBe('function');
		expect(typeof core.fromCurveToNumber).toBe('function');
		expect(typeof core.fromNumberToCurve).toBe('function');
	});

	it('should export utility functions', () => {
		expect(typeof core.encodeToASCII).toBe('function');
		expect(typeof core.u64ToBytesBigEndian).toBe('function');
		expect(typeof core.bytesToHex).toBe('function');
		expect(typeof core.hexToBytes).toBe('function');
		expect(typeof core.stringToUint8Array).toBe('function');
	});

	it('should export initializeWasm', () => {
		expect(typeof core.initializeWasm).toBe('function');
	});

	it('should export error classes', () => {
		expect(typeof core.IkaClientError).toBe('function');
		expect(typeof core.ObjectNotFoundError).toBe('function');
		expect(typeof core.InvalidObjectError).toBe('function');
		expect(typeof core.CacheError).toBe('function');
		expect(typeof core.NetworkError).toBe('function');
	});

	it('should NOT export raw wasm functions', () => {
		// These should be internal implementation details
		expect((core as any).create_sign_centralized_party_message).toBeUndefined();
		expect((core as any).encrypt_secret_share).toBeUndefined();
		expect((core as any).generate_secp_cg_keypair_from_seed).toBeUndefined();
	});
});
