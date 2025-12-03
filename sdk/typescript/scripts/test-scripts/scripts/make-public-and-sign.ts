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
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../../src/client/types';
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
	curve: Curve;
	signatureAlgorithm: SignatureAlgorithm;
	hash: Hash;
	dwalletId: string;
	dkgDigest: string;
	makePublicDigest: string;
	presignId: string;
	presignDigest: string;
	signId: string;
	signDigest: string;
	signature?: number[];
	error?: string;
}

export async function runMakePublicAndSign() {
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
		console.log(`\n=== Processing curve: ${curve} ===`);

		const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('test seed' + curve),
			curve,
		);

		// Register encryption key for zero-trust
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

		for (const combo of combos) {
			console.log(
				`\n--- Processing: ${combo.curve} - ${combo.signatureAlgorithm} - ${combo.hash} ---`,
			);

			try {
				// Step 1: Request zero-trust DKG
				console.log('Step 1: Requesting zero-trust DKG...');
				const dkgResult = await requestDKG(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					combo.curve,
					latestNetworkEncryptionKey.id,
					ALICE_IKA_COIN_ID,
				);

				console.log(`Zero-trust DKG requested. DWallet ID: ${dkgResult.dwalletId}`);

				// Step 2: Wait for AwaitingKeyHolderSignature
				console.log('Step 2: Waiting for DWallet to be in AwaitingKeyHolderSignature state...');
				const dwallet = await ikaClient.getDWalletInParticularState(
					dkgResult.dwalletId,
					'AwaitingKeyHolderSignature',
					{ timeout: 60000, interval: 2000 },
				);

				// Step 3: Accept user share
				console.log('Step 3: Accepting encrypted user share...');
				await acceptEncryptedUserShare(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					dwallet,
					dkgResult.encryptedUserSecretKeyShareId,
					dkgResult.userPublicOutput,
				);

				// Step 4: Wait for Active
				console.log('Step 4: Waiting for dwallet to become Active...');
				const activeDWallet = await ikaClient.getDWalletInParticularState(
					dkgResult.dwalletId,
					'Active',
					{ timeout: 60000, interval: 2000 },
				);

				console.log(`DWallet is now Active (zero-trust with encrypted shares)`);

				// Step 5: Make user share public
				console.log('Step 5: Making user share public...');
				const makePublicDigest = await makeUserSharePublic(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					activeDWallet as ZeroTrustDWallet,
					dkgResult.encryptedUserSecretKeyShareId,
					ALICE_IKA_COIN_ID,
				);

				console.log(`User share made public. Digest: ${makePublicDigest}`);

				// Step 6: Wait for DWallet to have public shares
				console.log('Step 6: Waiting for DWallet to have public shares...');
				const publicDWallet = await waitForPublicShares(ikaClient, dkgResult.dwalletId);

				console.log(`DWallet now has public shares (converted to public-share wallet)`);

				// Step 7: Request global presign
				console.log('Step 7: Requesting global presign...');
				const presignResult = await requestGlobalPresign(
					ikaClient,
					suiClient,
					combo.curve,
					combo.signatureAlgorithm,
					latestNetworkEncryptionKey.id,
					ALICE_IKA_COIN_ID,
				);

				// Step 8: Wait for presign completion
				console.log('Step 8: Waiting for presign to complete...');
				const presign = await ikaClient.getPresignInParticularState(
					presignResult.presignId,
					'Completed',
					{ timeout: 60000, interval: 2000 },
				);

				// Step 9: Sign with public shares
				console.log('Step 9: Signing with public shares...');
				const message = new TextEncoder().encode('test message for public share sign');
				const signResult = await signWithPublicShares(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					publicDWallet as ZeroTrustDWallet,
					presign,
					message,
					combo.curve,
					combo.signatureAlgorithm,
					combo.hash,
					ALICE_IKA_COIN_ID,
				);

				// Step 10: Wait for sign completion
				console.log('Step 10: Waiting for sign to complete...');
				const sign = await ikaClient.getSignInParticularState(
					signResult.signId,
					combo.curve,
					combo.signatureAlgorithm,
					'Completed',
					{ timeout: 60000, interval: 2000 },
				);

				console.log(`Sign completed with state: ${sign.state.$kind}`);

				results.push({
					curve: combo.curve,
					signatureAlgorithm: combo.signatureAlgorithm,
					hash: combo.hash,
					dwalletId: dkgResult.dwalletId,
					dkgDigest: dkgResult.digest,
					makePublicDigest,
					presignId: presignResult.presignId,
					presignDigest: presignResult.digest,
					signId: signResult.signId,
					signDigest: signResult.digest,
					signature: sign.state.$kind === 'Completed' ? sign.state.Completed?.signature : undefined,
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
					makePublicDigest: '',
					presignId: '',
					presignDigest: '',
					signId: '',
					signDigest: '',
					error: (error as Error).message,
				});
			}
		}
	}

	console.log('\n=== All Make Public and Sign Combinations Completed ===');
	console.dir(results, { depth: null });
}

async function requestDKG(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	curve: Curve,
	dwalletNetworkEncryptionKeyId: string,
	ikaCoinId: string,
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

	const result = await ikaTransaction.requestDWalletDKG({
		curve,
		dkgRequestInput,
		sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
		dwalletNetworkEncryptionKeyId,
		ikaCoin,
		suiCoin,
	});
	const dWalletCap = result[0];

	tx.transferObjects([dWalletCap], signerAddress);

	const txResult = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
		options: { showEvents: true },
	});

	const dkgEvent = txResult.events?.find((event) => event.type.includes('DWalletDKGRequestEvent'));
	if (!dkgEvent) throw new Error('DKG event not found');

	const dkgEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletDKGRequestEvent,
	).fromBase64(dkgEvent.bcs as string);

	const encryptedUserSecretKeyShareId =
		dkgEventData.event_data.user_secret_key_share.Encrypted?.encrypted_user_secret_key_share_id;
	if (!encryptedUserSecretKeyShareId) {
		throw new Error('Encrypted user secret key share ID not found');
	}

	return {
		dwalletId: dkgEventData.event_data.dwallet_id,
		encryptedUserSecretKeyShareId,
		userPublicOutput: Uint8Array.from(dkgEventData.event_data.user_public_output),
		digest: txResult.digest,
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

async function makeUserSharePublic(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: ZeroTrustDWallet,
	encryptedUserSecretKeyShareId: string,
	ikaCoinId: string,
): Promise<string> {
	// Get the encrypted user secret key share
	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareId,
	);
	if (!encryptedUserSecretKeyShare) {
		throw new Error('Encrypted user secret key share not found');
	}

	// Decrypt the user share
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(dwallet);
	const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
		dwallet,
		encryptedUserSecretKeyShare,
		protocolPublicParameters,
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

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet: dwallet,
		secretShare,
		ikaCoin,
		suiCoin,
	});

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
	});

	return result.digest;
}

async function waitForPublicShares(
	ikaClient: IkaClient,
	dwalletId: string,
): Promise<ZeroTrustDWallet> {
	// Poll for DWallet to have public shares
	let attempts = 0;
	const maxAttempts = 30;
	const interval = 2000;

	while (attempts < maxAttempts) {
		const dwallet = await ikaClient.getDWalletInParticularState(dwalletId, 'Active');

		if (dwallet && dwallet.public_user_secret_key_share) {
			return dwallet as ZeroTrustDWallet;
		}

		await new Promise((resolve) => setTimeout(resolve, interval));
		attempts++;
	}

	throw new Error('Timeout waiting for DWallet to have public shares');
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

async function signWithPublicShares(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: ZeroTrustDWallet,
	presign: any,
	message: Uint8Array,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	ikaCoinId: string,
) {
	// Verify that DWallet has public shares
	if (!dwallet.public_user_secret_key_share) {
		throw new Error('DWallet does not have public shares');
	}

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

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	// Sign without providing encrypted share - uses public shares automatically
	await ikaTransaction.requestSign({
		dWallet: dwallet,
		messageApproval,
		verifiedPresignCap,
		hashScheme: hash,
		presign,
		message,
		signatureScheme: signatureAlgorithm,
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

runMakePublicAndSign().catch(console.error);
