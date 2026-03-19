// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import * as sui from '../../src';

describe('Sui SDK exports', () => {
	it('should export Sui-specific classes', () => {
		expect(typeof sui.IkaClient).toBe('function');
		expect(typeof sui.IkaTransaction).toBe('function');
	});

	it('should export Sui-specific functions', () => {
		expect(typeof sui.getSuiAddress).toBe('function');
		expect(typeof sui.getUserOutputSignature).toBe('function');
		expect(typeof sui.getUserOutputSignatureForTransferredDWallet).toBe('function');
		expect(typeof sui.decryptUserShare).toBe('function');
		expect(typeof sui.prepareDKGAsync).toBe('function');
		expect(typeof sui.prepareImportedKeyDWalletVerification).toBe('function');
		expect(typeof sui.verifyAndGetDWalletDKGPublicOutput).toBe('function');
		expect(typeof sui.getNetworkConfig).toBe('function');
	});

	it('should export Sui-specific utilities', () => {
		expect(typeof sui.objResToBcs).toBe('function');
		expect(typeof sui.fetchAllDynamicFields).toBe('function');
	});

	it('should export transaction builder namespaces', () => {
		expect(typeof sui.coordinatorTransactions).toBe('object');
		expect(typeof sui.systemTransactions).toBe('object');
	});

	it('should export generated module namespaces', () => {
		expect(typeof sui.CoordinatorModule).toBe('object');
		expect(typeof sui.CoordinatorInnerModule).toBe('object');
		expect(typeof sui.SessionsManagerModule).toBe('object');
		expect(typeof sui.SystemModule).toBe('object');
	});

	it('should re-export core types and functions', () => {
		expect(typeof sui.createClassGroupsKeypair).toBe('function');
		expect(typeof sui.Ed25519Keypair).toBe('function');
		expect(typeof sui.UserShareEncryptionKeys).toBe('function');
		expect(sui.Curve.SECP256K1).toBe('SECP256K1');
		expect(sui.Hash.SHA256).toBe('SHA256');
		expect(sui.SignatureAlgorithm.ECDSASecp256k1).toBe('ECDSASecp256k1');
	});
});
