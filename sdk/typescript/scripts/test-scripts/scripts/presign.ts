import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction, TransactionObjectArgument } from '@mysten/sui/transactions';

import { CoordinatorInnerModule, SessionsManagerModule } from '../../../src';
import {
	fromNumberToCurve,
	fromNumberToSignatureAlgorithm,
} from '../../../src/client/hash-signature-validation';
import { IkaClient } from '../../../src/client/ika-client';
import { IkaTransaction } from '../../../src/client/ika-transaction';
import { getNetworkConfig } from '../../../src/client/network-configs';
import { Curve, Hash, SignatureAlgorithm } from '../../../src/client/types';
import { ALICE_IKA_COIN_ID, ikaClient, signer, signerAddress, suiClient } from './const';

type CurveSignatureHashCombination =
	| {
			curve: typeof Curve.SECP256K1;
			signatureAlgorithm: typeof SignatureAlgorithm.ECDSASecp256k1;
			hash: typeof Hash.KECCAK256 | typeof Hash.SHA256 | typeof Hash.DoubleSHA256;
	  }
	| {
			curve: typeof Curve.SECP256K1;
			signatureAlgorithm: typeof SignatureAlgorithm.Taproot;
			hash: typeof Hash.SHA256;
	  }
	| {
			curve: typeof Curve.SECP256R1;
			signatureAlgorithm: typeof SignatureAlgorithm.ECDSASecp256r1;
			hash: typeof Hash.SHA256;
	  }
	| {
			curve: typeof Curve.ED25519;
			signatureAlgorithm: typeof SignatureAlgorithm.EdDSA;
			hash: typeof Hash.SHA512;
	  }
	| {
			curve: typeof Curve.RISTRETTO;
			signatureAlgorithm: typeof SignatureAlgorithm.SchnorrkelSubstrate;
			hash: typeof Hash.Merlin;
	  };

// All supported combinations
const combinations: CurveSignatureHashCombination[] = [
	// SECP256K1 - ECDSASecp256k1
	{
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hash: Hash.KECCAK256,
	},
	{
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hash: Hash.SHA256,
	},
	{
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
		hash: Hash.DoubleSHA256,
	},
	// SECP256K1 - Taproot
	{
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.Taproot,
		hash: Hash.SHA256,
	},
	// SECP256R1 - ECDSASecp256r1
	{
		curve: Curve.SECP256R1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
		hash: Hash.SHA256,
	},
	// ED25519 - EdDSA
	{
		curve: Curve.ED25519,
		signatureAlgorithm: SignatureAlgorithm.EdDSA,
		hash: Hash.SHA512,
	},
	// RISTRETTO - SchnorrkelSubstrate
	{
		curve: Curve.RISTRETTO,
		signatureAlgorithm: SignatureAlgorithm.SchnorrkelSubstrate,
		hash: Hash.Merlin,
	},
];

export async function runPresign() {
	await ikaClient.initialize();

	const tx = new Transaction();

	const ikaCoin = tx.object(ALICE_IKA_COIN_ID);
	const suiCoin = tx.gas;

	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction: tx,
	});

	const caps: TransactionObjectArgument[] = [];
	// Request global presigns for all combinations
	for (const combo of combinations) {
		const unverifiedPresignCap = ikaTransaction.requestGlobalPresign({
			curve: combo.curve,
			signatureAlgorithm: combo.signatureAlgorithm,
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
			ikaCoin,
			suiCoin,
		});

		caps.push(unverifiedPresignCap);
	}

	tx.transferObjects(caps, signerAddress);

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
		options: {
			showEvents: true,
		},
	});

	const presignEvents = result.events?.filter((event) =>
		event.type.includes('PresignRequestEvent'),
	);

	const presignType: {
		presignId: string;
		curve: Curve;
		signatureAlgorithm: SignatureAlgorithm;
	}[] = [];

	for (const presignEvent of presignEvents ?? []) {
		const presignEventData = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.PresignRequestEvent,
		).fromBase64(presignEvent.bcs as string);

		presignType.push({
			presignId: presignEventData.event_data.presign_id,
			curve: fromNumberToCurve(presignEventData.event_data.curve),
			signatureAlgorithm: fromNumberToSignatureAlgorithm(
				fromNumberToCurve(presignEventData.event_data.curve),
				presignEventData.event_data.signature_algorithm,
			),
		});
	}

	console.log(result.digest);
	console.dir(presignType, { depth: null });
}

runPresign().catch(console.error);
