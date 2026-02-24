import { describe, it } from 'vitest';

import { Curve } from '../../src';
import { runCompleteDKGFlow, runCompleteSharedDKGFlow } from './helpers';

describe('DWallet Creation', () => {
	it('should create a new zero trust DWallet through the complete DKG v2 process - Secp256k1', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-secp256k1', Curve.SECP256K1);
	});

	it('should create a new zero trust DWallet through the complete DKG v2 process - Secp256r1', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-secp256r1', Curve.SECP256R1);
	});

	it('should create a new zero trust DWallet through the complete DKG v2 process - Ed25519', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-ed25519', Curve.ED25519);
	});

	it('should create a new zero trust DWallet through the complete DKG v2 process - Ristretto', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-ristretto', Curve.RISTRETTO);
	});

	it('should create a new shared DWallet through the complete DKG v2 process - Secp256k1', async () => {
		await runCompleteSharedDKGFlow(
			'dwallet-creation-shared-dkg-v2-test-secp256k1',
			Curve.SECP256K1,
		);
	});

	it('should create a new shared DWallet through the complete DKG v2 process - Secp256r1', async () => {
		await runCompleteSharedDKGFlow(
			'dwallet-creation-shared-dkg-v2-test-secp256r1',
			Curve.SECP256R1,
		);
	});

	it('should create a new shared DWallet through the complete DKG v2 process - Ed25519', async () => {
		await runCompleteSharedDKGFlow('dwallet-creation-shared-dkg-v2-test-ed25519', Curve.ED25519);
	});

	it('should create a new shared DWallet through the complete DKG v2 process - Ristretto', async () => {
		await runCompleteSharedDKGFlow(
			'dwallet-creation-shared-dkg-v2-test-ristretto',
			Curve.RISTRETTO,
		);
	});
});
