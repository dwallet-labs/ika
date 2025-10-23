import { describe, it } from 'vitest';

import { Curve, Hash, SignatureAlgorithm } from '../../src';
import { runCompleteDKGFlow, runCompleteSharedDKGFlowWithSign } from './helpers';

describe('DWallet Creation', () => {
	it('should sign during DKG v2 for a new zero trust DWallet - Secp256k1', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-secp256k1', Curve.SECP256K1, {
			message: Buffer.from('test message'),
			hashScheme: Hash.SHA256,
			signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		});
	});

	it('should sign during DKG v2 for a new zero trust DWallet - Secp256r1', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-secp256r1', Curve.SECP256R1, {
			message: Buffer.from('test message'),
			hashScheme: Hash.SHA256,
			signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
		});
	});

	it('should sign during DKG v2 for a new zero trust DWallet - Ed25519', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-ed25519', Curve.ED25519, {
			message: Buffer.from('test message'),
			hashScheme: Hash.SHA512,
			signatureAlgorithm: SignatureAlgorithm.EdDSA,
		});
	});

	it('should sign during DKG v2 for a new zero trust DWallet - Ristretto SchnorrkelSubstrate', async () => {
		await runCompleteDKGFlow(
			'dwallet-creation-dkg-v2-test-ristretto-schnorrkel-substrate',
			Curve.RISTRETTO,
			{
				message: Buffer.from('test message'),
				hashScheme: Hash.Merlin,
				signatureAlgorithm: SignatureAlgorithm.SchnorrkelSubstrate,
			},
		);
	});

	it('should sign during DKG v2 for a new zero trust DWallet - Secp256k1 Taproot', async () => {
		await runCompleteDKGFlow('dwallet-creation-dkg-v2-test-secp256k1-taproot', Curve.SECP256K1, {
			message: Buffer.from('test message'),
			hashScheme: Hash.SHA256,
			signatureAlgorithm: SignatureAlgorithm.Taproot,
		});
	});

	it('should sign during DKG v2 for a new shared DWallet - Secp256k1', async () => {
		await runCompleteSharedDKGFlowWithSign(
			'dwallet-creation-shared-dkg-v2-sign-test-secp256k1',
			Curve.SECP256K1,
			{
				message: Buffer.from('test message'),
				hashScheme: Hash.SHA256,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
			},
		);
	});

	it('should sign during DKG v2 for a new shared DWallet - Secp256r1', async () => {
		await runCompleteSharedDKGFlowWithSign(
			'dwallet-creation-shared-dkg-v2-sign-test-secp256r1',
			Curve.SECP256R1,
			{
				message: Buffer.from('test message'),
				hashScheme: Hash.SHA256,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
			},
		);
	});

	it('should sign during DKG v2 for a new shared DWallet - Ed25519', async () => {
		await runCompleteSharedDKGFlowWithSign(
			'dwallet-creation-shared-dkg-v2-sign-test-ed25519',
			Curve.ED25519,
			{
				message: Buffer.from('test message'),
				hashScheme: Hash.SHA512,
				signatureAlgorithm: SignatureAlgorithm.EdDSA,
			},
		);
	});

	it('should sign during DKG v2 for a new shared DWallet - Ristretto SchnorrkelSubstrate', async () => {
		await runCompleteSharedDKGFlowWithSign(
			'dwallet-creation-shared-dkg-v2-sign-test-ristretto-schnorrkel-substrate',
			Curve.RISTRETTO,
			{
				message: Buffer.from('test message'),
				hashScheme: Hash.Merlin,
				signatureAlgorithm: SignatureAlgorithm.SchnorrkelSubstrate,
			},
		);
	});

	it('should sign during DKG v2 for a new shared DWallet - Secp256k1 Taproot', async () => {
		await runCompleteSharedDKGFlowWithSign(
			'dwallet-creation-shared-dkg-v2-sign-test-secp256k1-taproot',
			Curve.SECP256K1,
			{
				message: Buffer.from('test message'),
				hashScheme: Hash.SHA256,
				signatureAlgorithm: SignatureAlgorithm.Taproot,
			},
		);
	});
});
