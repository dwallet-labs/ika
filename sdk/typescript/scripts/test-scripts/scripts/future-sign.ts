import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';

import { CoordinatorInnerModule, SessionsManagerModule } from '../../../src';
import { createRandomSessionIdentifier, prepareDKGAsync } from '../../../src/client/cryptography';
import { IkaClient } from '../../../src/client/ika-client';
import { IkaTransaction } from '../../../src/client/ika-transaction';
import { getNetworkConfig } from '../../../src/client/network-configs';
import {
	Curve,
	DWallet,
	Hash,
	SharedDWallet,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../../src/client/types';
import { UserShareEncryptionKeys } from '../../../src/client/user-share-encryption-keys';
import { ALICE_IKA_COIN_ID, ikaClient, signer, signerAddress, suiClient } from './const';

type DWalletType = 'zero-trust' | 'shared';

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

const combinations: CurveSignatureHashCombination[] = [
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
	{
		curve: Curve.SECP256K1,
		signatureAlgorithm: SignatureAlgorithm.Taproot,
		hash: Hash.SHA256,
	},
	{
		curve: Curve.SECP256R1,
		signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
		hash: Hash.SHA256,
	},
	{
		curve: Curve.ED25519,
		signatureAlgorithm: SignatureAlgorithm.EdDSA,
		hash: Hash.SHA512,
	},
	{
		curve: Curve.RISTRETTO,
		signatureAlgorithm: SignatureAlgorithm.SchnorrkelSubstrate,
		hash: Hash.Merlin,
	},
];

interface CombinationResult {
	dwalletType: DWalletType;
	curve: Curve;
	signatureAlgorithm: SignatureAlgorithm;
	hash: Hash;
	dwalletId: string;
	dkgDigest: string;
	presignId: string;
	presignDigest: string;
	futureSignDigest: string;
	partialSignatureId: string;
	completeSignDigest: string;
	signId: string;
	signature?: number[];
	error?: string;
}

export async function runFutureSign(dwalletType: DWalletType = 'zero-trust') {
	await ikaClient.initialize();

	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

	const results: CombinationResult[] = [];

	const curveMap = new Map<Curve, CurveSignatureHashCombination[]>();
	for (const combo of combinations) {
		if (!curveMap.has(combo.curve)) {
			curveMap.set(combo.curve, []);
		}
		curveMap.get(combo.curve)!.push(combo);
	}

	for (const [curve, combos] of curveMap) {
		console.log(`\n=== Processing curve: ${curve} (${dwalletType}) ===`);

		const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('test seed' + curve),
			curve,
		);

		// Only register encryption key for zero-trust
		if (dwalletType === 'zero-trust') {
			const encryptionKeyTx = new Transaction();
			encryptionKeyTx.setSender(signerAddress);
			encryptionKeyTx.setGasBudget(1_000_000_000);
			const ikaTransactionForEncryption = new IkaTransaction({
				ikaClient,
				transaction: encryptionKeyTx,
				userShareEncryptionKeys,
			});

			await ikaTransactionForEncryption.registerEncryptionKey({ curve });

			console.log(`Registering encryption key for curve ${curve}...`);
			await suiClient
				.signAndExecuteTransaction({
					transaction: encryptionKeyTx,
					signer: signer,
				})
				.catch((error) => {
					console.log('The encryption key was already registered');
				});
		}

		for (const combo of combos) {
			console.log(
				`\n--- Processing: ${combo.curve} - ${combo.signatureAlgorithm} - ${combo.hash} ---`,
			);

			try {
				// Step 1: Request DKG (zero-trust or shared)
				console.log(`Step 1: Requesting ${dwalletType} DKG...`);
				const dkgResult = await requestDKG(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					combo.curve,
					latestNetworkEncryptionKey.id,
					ALICE_IKA_COIN_ID,
					dwalletType,
				);

				console.log(`DKG requested. DWallet ID: ${dkgResult.dwalletId}`);

				// Step 2: Handle activation based on dwallet type
				let activeDWallet: ZeroTrustDWallet | SharedDWallet;

				if (dwalletType === 'zero-trust') {
					// Wait for AwaitingKeyHolderSignature
					console.log('Step 2a: Waiting for DWallet to be in AwaitingKeyHolderSignature state...');
					const dwallet = await ikaClient.getDWalletInParticularState(
						dkgResult.dwalletId,
						'AwaitingKeyHolderSignature',
						{ timeout: 60000, interval: 2000 },
					);

					// Accept user share
					console.log('Step 2b: Accepting encrypted user share...');
					await acceptEncryptedUserShare(
						ikaClient,
						suiClient,
						userShareEncryptionKeys,
						dwallet,
						dkgResult.encryptedUserSecretKeyShareId!,
						dkgResult.userPublicOutput!,
					);

					// Wait for Active
					console.log('Step 2c: Waiting for dwallet to become Active...');
					activeDWallet = (await ikaClient.getDWalletInParticularState(
						dkgResult.dwalletId,
						'Active',
						{ timeout: 60000, interval: 2000 },
					)) as ZeroTrustDWallet;
				} else {
					// Shared dwallet goes directly to Active
					console.log('Step 2: Waiting for dwallet to become Active...');
					activeDWallet = (await ikaClient.getDWalletInParticularState(
						dkgResult.dwalletId,
						'Active',
						{ timeout: 60000, interval: 2000 },
					)) as SharedDWallet;
				}

				console.log(`DWallet is now Active`);

				// Step 3: Request global presign
				console.log('Step 3: Requesting global presign...');
				const presignResult = await requestGlobalPresign(
					ikaClient,
					suiClient,
					combo.curve,
					combo.signatureAlgorithm,
					latestNetworkEncryptionKey.id,
					ALICE_IKA_COIN_ID,
				);

				// Step 4: Wait for presign completion
				console.log('Step 4: Waiting for presign to complete...');
				const presign = await ikaClient.getPresignInParticularState(
					presignResult.presignId,
					'Completed',
					{ timeout: 60000, interval: 2000 },
				);

				// Step 5: Request future sign
				console.log('Step 5: Requesting future sign...');
				const message = new TextEncoder().encode('test message for future sign');
				const futureSignResult = await requestFutureSign(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					activeDWallet,
					presign,
					dkgResult.encryptedUserSecretKeyShareId,
					message,
					combo.curve,
					combo.signatureAlgorithm,
					combo.hash,
					ALICE_IKA_COIN_ID,
					dwalletType,
				);

				// Step 6: Wait for partial signature verification
				console.log('Step 6: Waiting for partial signature to be verified...');
				const partialSignature = await ikaClient.getPartialUserSignatureInParticularState(
					futureSignResult.partialSignatureId,
					'NetworkVerificationCompleted',
					{ timeout: 60000, interval: 2000 },
				);

				// Step 7: Complete future sign with message approval
				console.log('Step 7: Completing future sign with message approval...');
				const completeSignResult = await completeFutureSign(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					activeDWallet,
					partialSignature.cap_id,
					message,
					combo.curve,
					combo.signatureAlgorithm,
					combo.hash,
					ALICE_IKA_COIN_ID,
				);

				// Step 8: Wait for sign completion
				console.log('Step 8: Waiting for sign to complete...');
				const sign = await ikaClient.getSignInParticularState(
					completeSignResult.signId,
					combo.curve,
					combo.signatureAlgorithm,
					'Completed',
					{ timeout: 60000, interval: 2000 },
				);

				console.log(`Sign completed with state: ${sign.state.$kind}`);

				results.push({
					dwalletType,
					curve: combo.curve,
					signatureAlgorithm: combo.signatureAlgorithm,
					hash: combo.hash,
					dwalletId: dkgResult.dwalletId,
					dkgDigest: dkgResult.digest,
					presignId: presignResult.presignId,
					presignDigest: presignResult.digest,
					futureSignDigest: futureSignResult.digest,
					partialSignatureId: futureSignResult.partialSignatureId,
					completeSignDigest: completeSignResult.digest,
					signId: completeSignResult.signId,
					signature: sign.state.$kind === 'Completed' ? sign.state.Completed?.signature : undefined,
				});

				console.log('✅ Combination completed successfully!');
			} catch (error) {
				console.error(`❌ Error processing combination: ${(error as Error).message}`);
				results.push({
					dwalletType,
					curve: combo.curve,
					signatureAlgorithm: combo.signatureAlgorithm,
					hash: combo.hash,
					dwalletId: '',
					dkgDigest: '',
					presignId: '',
					presignDigest: '',
					futureSignDigest: '',
					partialSignatureId: '',
					completeSignDigest: '',
					signId: '',
					error: (error as Error).message,
				});
			}
		}
	}

	console.log(`\n=== All ${dwalletType} Combinations Completed ===`);
	console.dir(results, { depth: null });
}

async function requestDKG(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	curve: Curve,
	dwalletNetworkEncryptionKeyId: string,
	ikaCoinId: string,
	dwalletType: DWalletType,
) {
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

	let dWalletCap;

	if (dwalletType === 'zero-trust') {
		const result = await ikaTransaction.requestDWalletDKG({
			curve,
			dkgRequestInput,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
			dwalletNetworkEncryptionKeyId,
			ikaCoin,
			suiCoin,
		});
		dWalletCap = result[0];
	} else {
		[dWalletCap] = await ikaTransaction.requestDWalletDKGWithPublicUserShare({
			curve,
			publicKeyShareAndProof: dkgRequestInput.userDKGMessage,
			publicUserSecretKeyShare: dkgRequestInput.userSecretKeyShare,
			userPublicOutput: dkgRequestInput.userPublicOutput,
			sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
			dwalletNetworkEncryptionKeyId,
			ikaCoin,
			suiCoin,
		});
	}

	tx.transferObjects([dWalletCap], signerAddress);

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
		options: { showEvents: true },
	});

	const dkgEvent = result.events?.find((event) => event.type.includes('DWalletDKGRequestEvent'));
	if (!dkgEvent) throw new Error('DKG event not found');

	const dkgEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletDKGRequestEvent,
	).fromBase64(dkgEvent.bcs as string);

	let encryptedUserSecretKeyShareId: string | undefined;
	let userPublicOutput: Uint8Array | undefined;

	if (dwalletType === 'zero-trust') {
		encryptedUserSecretKeyShareId =
			dkgEventData.event_data.user_secret_key_share.Encrypted?.encrypted_user_secret_key_share_id;
		if (!encryptedUserSecretKeyShareId) {
			throw new Error('Encrypted user secret key share ID not found');
		}
		userPublicOutput = Uint8Array.from(dkgEventData.event_data.user_public_output);
	}

	return {
		dwalletId: dkgEventData.event_data.dwallet_id,
		encryptedUserSecretKeyShareId,
		userPublicOutput,
		digest: result.digest,
	};
}

async function acceptEncryptedUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: DWallet,
	encryptedUserSecretKeyShareId: string,
	userPublicOutput: Uint8Array,
) {
	const tx = new Transaction();
	tx.setSender(signerAddress);
	tx.setGasBudget(1_000_000_000);

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction: tx,
		userShareEncryptionKeys,
	});

	await ikaTransaction.acceptEncryptedUserShare({
		dWallet: dwallet as ZeroTrustDWallet,
		encryptedUserSecretKeyShareId,
		userPublicOutput,
	});

	await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
	});
}

async function requestGlobalPresign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	dwalletNetworkEncryptionKeyId: string,
	ikaCoinId: string,
) {
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
		options: { showEvents: true },
	});

	const presignEvent = result.events?.find((event) => event.type.includes('PresignRequestEvent'));
	if (!presignEvent) throw new Error('Presign event not found');

	const presignEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.PresignRequestEvent,
	).fromBase64(presignEvent.bcs as string);

	return {
		presignId: presignEventData.event_data.presign_id,
		digest: result.digest,
	};
}

async function requestFutureSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: ZeroTrustDWallet | SharedDWallet,
	presign: any,
	encryptedUserSecretKeyShareId: string | undefined,
	message: Uint8Array,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	ikaCoinId: string,
	dwalletType: DWalletType,
) {
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

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({ presign });

	let unverifiedPartialUserSignatureCap;

	if (dwalletType === 'zero-trust') {
		const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
			encryptedUserSecretKeyShareId!,
		);
		if (!encryptedUserSecretKeyShare) {
			throw new Error('Encrypted user secret key share not found');
		}

		unverifiedPartialUserSignatureCap = await ikaTransaction.requestFutureSign({
			dWallet: dwallet as ZeroTrustDWallet,
			verifiedPresignCap,
			presign,
			encryptedUserSecretKeyShare,
			message,
			hashScheme: hash,
			signatureScheme: signatureAlgorithm,
			ikaCoin,
			suiCoin,
		});
	} else {
		unverifiedPartialUserSignatureCap = await ikaTransaction.requestFutureSign({
			dWallet: dwallet as SharedDWallet,
			verifiedPresignCap,
			presign,
			message,
			hashScheme: hash,
			signatureScheme: signatureAlgorithm,
			ikaCoin,
			suiCoin,
		});
	}

	tx.transferObjects([unverifiedPartialUserSignatureCap], signerAddress);

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
		options: { showEvents: true },
	});

	const futureSignEvent = result.events?.find((event) =>
		event.type.includes('FutureSignRequestEvent'),
	);
	if (!futureSignEvent) throw new Error('Future sign event not found');

	const futureSignEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.FutureSignRequestEvent,
	).fromBase64(futureSignEvent.bcs as string);

	return {
		partialSignatureId: futureSignEventData.event_data.partial_centralized_signed_message_id,
		digest: result.digest,
	};
}

async function completeFutureSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: ZeroTrustDWallet | SharedDWallet,
	partialUserSignatureCapId: string,
	message: Uint8Array,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	ikaCoinId: string,
) {
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

	const messageApproval = ikaTransaction.approveMessage({
		dWalletCap: dwallet.dwallet_cap_id,
		curve,
		signatureAlgorithm,
		hashScheme: hash,
		message,
	});

	ikaTransaction.futureSign({
		partialUserSignatureCap: partialUserSignatureCapId,
		messageApproval,
		ikaCoin,
		suiCoin,
	});

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
		options: { showEvents: true },
	});

	const signEvent = result.events?.find((event) => event.type.includes('SignRequestEvent'));
	if (!signEvent) throw new Error('Sign event not found');

	const signEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.SignRequestEvent,
	).fromBase64(signEvent.bcs as string);

	return {
		signId: signEventData.event_data.sign_id,
		digest: result.digest,
	};
}

// Change this to 'shared' to run shared dwallet tests
const DWALLET_TYPE: DWalletType = 'shared';

runFutureSign(DWALLET_TYPE).catch(console.error);
