import { describe, it } from 'vitest';

import { Curve, Hash, SignatureAlgorithm } from '../../src';
import { runCompleteDKGFlow } from './helpers';

describe('DWallet Creation', () => {
	it('should sign during DKG v2 for a new zero trust DWallet - Secp256k1', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-secp256k1', Curve.SECP256K1, {
			message: Buffer.from('test message'),
			hashScheme: Hash.SHA256,
			signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		});
	});
});
