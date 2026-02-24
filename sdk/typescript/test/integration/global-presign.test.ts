import { describe, it } from 'vitest';

import { Curve, SignatureAlgorithm } from '../../src';
import { runGlobalPresignTest } from './helpers';

describe('Global Presign', () => {
	it('should create a global presign - Secp256k1 ECDSASecp256k1', async () => {
		await runGlobalPresignTest(
			'global-presign-test-secp256k1',
			Curve.SECP256K1,
			SignatureAlgorithm.ECDSASecp256k1,
		);
	});

	it('should create a global presign - Secp256r1 ECDSASecp256r1', async () => {
		await runGlobalPresignTest(
			'global-presign-test-secp256r1',
			Curve.SECP256R1,
			SignatureAlgorithm.ECDSASecp256r1,
		);
	});

	it('should create a global presign - Ed25519 EdDSA', async () => {
		await runGlobalPresignTest(
			'global-presign-test-ed25519',
			Curve.ED25519,
			SignatureAlgorithm.EdDSA,
		);
	});

	it('should create a global presign - Ristretto SchnorrkelSubstrate', async () => {
		await runGlobalPresignTest(
			'global-presign-test-ristretto-schnorrkel-substrate',
			Curve.RISTRETTO,
			SignatureAlgorithm.SchnorrkelSubstrate,
		);
	});

	it('should create a global presign - Secp256k1 Taproot', async () => {
		await runGlobalPresignTest(
			'global-presign-test-secp256k1-taproot',
			Curve.SECP256K1,
			SignatureAlgorithm.Taproot,
		);
	});
});
