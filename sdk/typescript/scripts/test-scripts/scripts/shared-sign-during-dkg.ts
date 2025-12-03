import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';

import { CoordinatorInnerModule, SessionsManagerModule } from '../../../src';
import { createRandomSessionIdentifier, prepareDKGAsync } from '../../../src/client/cryptography';
import {
	fromNumberToCurve,
	fromNumberToHash,
	fromNumberToSignatureAlgorithm,
	ValidHashForSignature,
} from '../../../src/client/hash-signature-validation';
import { IkaClient } from '../../../src/client/ika-client';
import { IkaTransaction } from '../../../src/client/ika-transaction';
import { getNetworkConfig } from '../../../src/client/network-configs';
import { Curve, Hash, SignatureAlgorithm } from '../../../src/client/types';
import { UserShareEncryptionKeys } from '../../../src/client/user-share-encryption-keys';
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

interface CombinationResult {
	curve: Curve;
	signatureAlgorithm: SignatureAlgorithm;
	hash: Hash;
	dwalletId: string;
	dkgDigest: string;
	presignId: string;
	signId: string;
	signature?: number[];
	dwalletState?: string;
	signState?: string;
	error?: string;
}

export async function runSharedSignDuringDKG() {
	await ikaClient.initialize();

	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

	const results: CombinationResult[] = [];

	// Group combinations by curve
	const curveMap = new Map<Curve, CurveSignatureHashCombination[]>();
	for (const combo of combinations) {
		if (!curveMap.has(combo.curve)) {
			curveMap.set(combo.curve, []);
		}
		curveMap.get(combo.curve)!.push(combo);
	}

	for (const [curve, combos] of curveMap) {
		console.log(`\n=== Processing curve: ${curve} ===`);

		const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('test seed' + curve),
			curve,
		);

		// Process each combination for this curve
		for (const combo of combos) {
			console.log(
				`\n--- Processing: ${combo.curve} - ${combo.signatureAlgorithm} - ${combo.hash} ---`,
			);

			try {
				// Step 1: Request global presign first
				console.log('Step 1: Requesting global presign...');
				const presignResult = await requestGlobalPresign(
					ikaClient,
					suiClient,
					combo.curve,
					combo.signatureAlgorithm,
					latestNetworkEncryptionKey.id,
					ALICE_IKA_COIN_ID,
				);

				console.log(
					`Presign requested. Presign ID: ${presignResult.presignId}, Digest: ${presignResult.digest}`,
				);

				// Step 2: Wait for presign to complete
				console.log('Step 2: Waiting for presign to complete...');
				const presign = await ikaClient.getPresignInParticularState(
					presignResult.presignId,
					'Completed',
					{
						timeout: 60000,
						interval: 2000,
					},
				);

				console.log(`Presign completed with state: ${presign.state.$kind}`);

				// Step 3: Request Shared DKG with sign-during-DKG
				console.log('Step 3: Requesting Shared DKG with sign-during-DKG...');
				const dkgResult = await requestSharedDKGWithSignDuringDKG(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					combo.curve,
					combo.signatureAlgorithm,
					combo.hash,
					presign,
					latestNetworkEncryptionKey.id,
					ALICE_IKA_COIN_ID,
				);

				console.log(
					`Shared DKG with sign-during-DKG requested. DWallet ID: ${dkgResult.dwalletId}, Sign ID: ${dkgResult.signId}, Digest: ${dkgResult.digest}`,
				);

				// Step 4: Wait for DWallet to become Active
				console.log('Step 4: Waiting for DWallet to become Active...');
				const activeDWallet = await ikaClient.getDWalletInParticularState(
					dkgResult.dwalletId,
					'Active',
					{
						timeout: 60000,
						interval: 2000,
					},
				);

				console.log(`DWallet is now Active, Kind: ${activeDWallet.kind}`);

				// Step 5: Wait for sign to complete
				console.log('Step 5: Waiting for sign to complete...');
				const sign = await ikaClient.getSignInParticularState(
					dkgResult.signId,
					combo.curve,
					combo.signatureAlgorithm,
					'Completed',
					{
						timeout: 60000,
						interval: 2000,
					},
				);

				console.log(`Sign completed with state: ${sign.state.$kind}`);

				results.push({
					curve: combo.curve,
					signatureAlgorithm: combo.signatureAlgorithm,
					hash: combo.hash,
					dwalletId: dkgResult.dwalletId,
					dkgDigest: dkgResult.digest,
					presignId: presignResult.presignId,
					signId: dkgResult.signId,
					signature: sign.state.$kind === 'Completed' ? sign.state.Completed?.signature : undefined,
					dwalletState: activeDWallet.state.$kind,
					signState: sign.state.$kind,
				});

				console.log('✅ Combination completed successfully!');
			} catch (error) {
				console.error(`❌ Error processing combination: ${(error as Error).message}`);
				results.push({
					curve: combo.curve,
					signatureAlgorithm: combo.signatureAlgorithm,
					hash: combo.hash,
					dwalletId: '',
					dkgDigest: '',
					presignId: '',
					signId: '',
					error: (error as Error).message,
				});
			}
		}
	}

	console.log('\n=== All Combinations Completed ===');
	console.dir(results, { depth: null });
}

async function requestGlobalPresign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	dwalletNetworkEncryptionKeyId: string,
	ikaCoinId: string,
): Promise<{
	presignId: string;
	digest: string;
}> {
	const tx = new Transaction();
	tx.setSender(signerAddress);
	tx.setGasBudget(1_000_000_000);
	const ikaCoin = tx.object(ikaCoinId);
	const suiCoin = tx.gas;

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction: tx,
	});

	const unverifiedPresignCap = ikaTransaction.requestGlobalPresign({
		curve,
		signatureAlgorithm,
		dwalletNetworkEncryptionKeyId,
		ikaCoin,
		suiCoin,
	});

	tx.transferObjects([unverifiedPresignCap], signerAddress);

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
		options: {
			showEvents: true,
		},
	});

	const presignEvent = result.events?.find((event) => event.type.includes('PresignRequestEvent'));

	if (!presignEvent) {
		throw new Error('Presign event not found');
	}

	const presignEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.PresignRequestEvent,
	).fromBase64(presignEvent.bcs as string);

	return {
		presignId: presignEventData.event_data.presign_id,
		digest: result.digest,
	};
}

async function requestSharedDKGWithSignDuringDKG(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	presign: any,
	dwalletNetworkEncryptionKeyId: string,
	ikaCoinId: string,
): Promise<{
	dwalletId: string;
	signId: string;
	digest: string;
}> {
	const randomSessionIdentifier = createRandomSessionIdentifier();

	const dkgRequestInput = await prepareDKGAsync(
		ikaClient,
		curve,
		userShareEncryptionKeys,
		randomSessionIdentifier,
		signerAddress,
	);

	const tx = new Transaction();
	tx.setSender(signerAddress);
	tx.setGasBudget(1_000_000_000);
	const ikaCoin = tx.object(ikaCoinId);
	const suiCoin = tx.gas;

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction: tx,
		userShareEncryptionKeys,
	});

	const message = new TextEncoder().encode('test message for sign-during-dkg');

	let dWalletCap: any;

	// Use explicit conditional logic to properly narrow types for signing during DKG
	if (signatureAlgorithm === SignatureAlgorithm.ECDSASecp256k1) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
			curve,
			publicKeyShareAndProof: dkgRequestInput.userDKGMessage,
			publicUserSecretKeyShare: dkgRequestInput.userSecretKeyShare,
			userPublicOutput: dkgRequestInput.userPublicOutput,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
			dwalletNetworkEncryptionKeyId,
			ikaCoin,
			suiCoin,
			signDuringDKGRequest: {
				message,
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.ECDSASecp256k1>,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
			},
		});
	} else if (signatureAlgorithm === SignatureAlgorithm.Taproot) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
			curve,
			publicKeyShareAndProof: dkgRequestInput.userDKGMessage,
			publicUserSecretKeyShare: dkgRequestInput.userSecretKeyShare,
			userPublicOutput: dkgRequestInput.userPublicOutput,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
			dwalletNetworkEncryptionKeyId,
			ikaCoin,
			suiCoin,
			signDuringDKGRequest: {
				message,
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.Taproot>,
				signatureAlgorithm: SignatureAlgorithm.Taproot,
			},
		});
	} else if (signatureAlgorithm === SignatureAlgorithm.ECDSASecp256r1) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
			curve,
			publicKeyShareAndProof: dkgRequestInput.userDKGMessage,
			publicUserSecretKeyShare: dkgRequestInput.userSecretKeyShare,
			userPublicOutput: dkgRequestInput.userPublicOutput,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
			dwalletNetworkEncryptionKeyId,
			ikaCoin,
			suiCoin,
			signDuringDKGRequest: {
				message,
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.ECDSASecp256r1>,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
			},
		});
	} else if (signatureAlgorithm === SignatureAlgorithm.EdDSA) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
			curve,
			publicKeyShareAndProof: dkgRequestInput.userDKGMessage,
			publicUserSecretKeyShare: dkgRequestInput.userSecretKeyShare,
			userPublicOutput: dkgRequestInput.userPublicOutput,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
			dwalletNetworkEncryptionKeyId,
			ikaCoin,
			suiCoin,
			signDuringDKGRequest: {
				message,
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.EdDSA>,
				signatureAlgorithm: SignatureAlgorithm.EdDSA,
			},
		});
	} else if (signatureAlgorithm === SignatureAlgorithm.SchnorrkelSubstrate) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
			curve,
			publicKeyShareAndProof: dkgRequestInput.userDKGMessage,
			publicUserSecretKeyShare: dkgRequestInput.userSecretKeyShare,
			userPublicOutput: dkgRequestInput.userPublicOutput,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
			dwalletNetworkEncryptionKeyId,
			ikaCoin,
			suiCoin,
			signDuringDKGRequest: {
				message,
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.SchnorrkelSubstrate>,
				signatureAlgorithm: SignatureAlgorithm.SchnorrkelSubstrate,
			},
		});
	}

	tx.transferObjects([dWalletCap], signerAddress);

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
		options: {
			showEvents: true,
		},
	});

	const dkgEvent = result.events?.find((event) => event.type.includes('DWalletDKGRequestEvent'));

	if (!dkgEvent) {
		throw new Error('DKG event not found');
	}

	const dkgEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletDKGRequestEvent,
	).fromBase64(dkgEvent.bcs as string);

	const signId = dkgEventData.event_data.sign_during_dkg_request?.sign_id;

	if (!signId) {
		throw new Error('Sign ID not found in sign-during-DKG request');
	}

	return {
		dwalletId: dkgEventData.event_data.dwallet_id,
		signId,
		digest: result.digest,
	};
}

runSharedSignDuringDKG().catch(console.error);
