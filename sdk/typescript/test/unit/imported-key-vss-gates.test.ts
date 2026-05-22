// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { describe, expect, it } from 'vitest';

import { validateImportedKeySignatureAlgorithm } from '../../src/client/hash-signature-validation';
import { SignatureAlgorithm } from '../../src/client/types';

describe('VSS gates', () => {
	describe('validateImportedKeySignatureAlgorithm', () => {
		it.each([
			SignatureAlgorithm.TaprootVSS,
			SignatureAlgorithm.EdDSAVSS,
			SignatureAlgorithm.SchnorrkelSubstrateVSS,
		])('rejects VSS variant %s', (algo) => {
			expect(() => validateImportedKeySignatureAlgorithm(algo)).toThrow(
				/cannot be used with imported-key dWallets/,
			);
		});

		it.each([
			SignatureAlgorithm.ECDSASecp256k1,
			SignatureAlgorithm.ECDSASecp256r1,
			SignatureAlgorithm.Taproot,
			SignatureAlgorithm.EdDSA,
			SignatureAlgorithm.SchnorrkelSubstrate,
		])('accepts non-VSS variant %s', (algo) => {
			expect(() => validateImportedKeySignatureAlgorithm(algo)).not.toThrow();
		});
	});
});
