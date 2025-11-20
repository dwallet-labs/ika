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
import {
	Curve,
	DWallet,
	Hash,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../../src/client/types';
import { UserShareEncryptionKeys } from '../../../src/client/user-share-encryption-keys';
import { ALICE_IKA_COIN_ID, signer, signerAddress } from './const';

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
	presignDigest: string;
	signId: string;
	signDigest: string;
	signature?: number[];
	error?: string;
}

export async function runDKGPresignSign() {
	const suiClient = new SuiClient({ url: 'https://sui-testnet-rpc.publicnode.com' });

	const ikaClient = new IkaClient({
		suiClient,
		config: getNetworkConfig('testnet'),
	});

	await ikaClient.initialize();

	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

	const results: CombinationResult[] = [];

	// Group combinations by curve to avoid redundant encryption key registration
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

		// Register encryption key once per curve
		const encryptionKeyTx = new Transaction();
		encryptionKeyTx.setSender(signerAddress);
		encryptionKeyTx.setGasBudget(1_000_000_000);
		const ikaTransactionForEncryption = new IkaTransaction({
			ikaClient,
			transaction: encryptionKeyTx,
			userShareEncryptionKeys,
		});

		await ikaTransactionForEncryption.registerEncryptionKey({
			curve,
		});

		console.log(`Registering encryption key for curve ${curve}...`);
		await suiClient
			.signAndExecuteTransaction({
				transaction: encryptionKeyTx,
				signer: signer,
			})
			.catch((error) => {
				console.log('The encryption key was already registered');
			});

		// Process each combination for this curve
		for (const combo of combos) {
			console.log(
				`\n--- Processing: ${combo.curve} - ${combo.signatureAlgorithm} - ${combo.hash} ---`,
			);

			try {
				// Step 1: Request DKG
				console.log('Step 1: Requesting DKG...');
				const dkgResult = await requestDKG(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					combo.curve,
					latestNetworkEncryptionKey.id,
					ALICE_IKA_COIN_ID,
				);

				console.log(
					`DKG requested. DWallet ID: ${dkgResult.dwalletId}, Digest: ${dkgResult.digest}`,
				);

				// Step 2: Wait for DWallet to be in AwaitingKeyHolderSignature state
				console.log('Step 2: Waiting for DWallet to be in AwaitingKeyHolderSignature state...');
				const dwallet = await ikaClient.getDWalletInParticularState(
					dkgResult.dwalletId,
					'AwaitingKeyHolderSignature',
					{
						timeout: 60000,
						interval: 2000,
					},
				);

				console.log(
					`DWallet is now in ${dwallet.state.$kind} state, Cap ID: ${dwallet.dwallet_cap_id}`,
				);

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

				console.log(
					`Presign requested. Presign ID: ${presignResult.presignId}, Digest: ${presignResult.digest}`,
				);

				// Step 4: Wait for presign to complete
				console.log('Step 4: Waiting for presign to complete...');
				const presign = await ikaClient.getPresignInParticularState(
					presignResult.presignId,
					'Completed',
					{
						timeout: 60000,
						interval: 2000,
					},
				);

				console.log(`Presign completed with state: ${presign.state.$kind}`);

				// Step 5: Accept encrypted user share and activate dwallet
				console.log('Step 5: Accepting encrypted user share...');
				await acceptEncryptedUserShare(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					dwallet,
					dkgResult.encryptedUserSecretKeyShareId,
					dkgResult.userPublicOutput,
				);

				console.log('Encrypted user share accepted');

				// Step 6: Wait for dwallet to become Active
				console.log('Step 6: Waiting for dwallet to become Active...');
				const activeDWallet = await ikaClient.getDWalletInParticularState(
					dkgResult.dwalletId,
					'Active',
					{
						timeout: 60000,
						interval: 2000,
					},
				);

				console.log(`DWallet is now Active`);

				// Step 7: Request sign
				console.log('Step 7: Requesting sign...');
				const message = new TextEncoder().encode('test message for sign');
				const signResult = await requestSign(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					activeDWallet as ZeroTrustDWallet,
					presign,
					dkgResult.encryptedUserSecretKeyShareId,
					message,
					combo.curve,
					combo.signatureAlgorithm,
					combo.hash,
					ALICE_IKA_COIN_ID,
				);

				console.log(`Sign requested. Sign ID: ${signResult.signId}, Digest: ${signResult.digest}`);

				// Step 8: Wait for sign to complete
				console.log('Step 8: Waiting for sign to complete...');
				const sign = await ikaClient.getSignInParticularState(
					signResult.signId,
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
					presignId: '',
					presignDigest: '',
					signId: '',
					signDigest: '',
					error: (error as Error).message,
				});
			}
		}
	}

	console.log('\n=== All Combinations Completed ===');
	console.dir(results, { depth: null });
}

async function requestDKG(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	curve: Curve,
	dwalletNetworkEncryptionKeyId: string,
	ikaCoinId: string,
): Promise<{
	dwalletId: string;
	encryptedUserSecretKeyShareId: string;
	userPublicOutput: Uint8Array;
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

	const [dWalletCap, _] = await ikaTransaction.requestDWalletDKG({
		curve,
		dkgRequestInput,
		sessionIdentifier: ikaTransaction.registerSessionIdentifier(randomSessionIdentifier),
		dwalletNetworkEncryptionKeyId,
		ikaCoin,
		suiCoin,
	});

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

	const encryptedUserSecretKeyShareId =
		dkgEventData.event_data.user_secret_key_share.Encrypted?.encrypted_user_secret_key_share_id;

	if (!encryptedUserSecretKeyShareId) {
		throw new Error('Encrypted user secret key share ID not found');
	}

	return {
		dwalletId: dkgEventData.event_data.dwallet_id,
		encryptedUserSecretKeyShareId,
		digest: result.digest,
		userPublicOutput: Uint8Array.from(dkgEventData.event_data.user_public_output),
	};
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

async function acceptEncryptedUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: DWallet,
	encryptedUserSecretKeyShareId: string,
	userPublicOutput: Uint8Array,
): Promise<string> {
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

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
	});

	return result.digest;
}

async function requestSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: ZeroTrustDWallet,
	presign: any,
	encryptedUserSecretKeyShareId: string,
	message: Uint8Array,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	ikaCoinId: string,
): Promise<{
	signId: string;
	digest: string;
}> {
	// Get the encrypted user secret key share
	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareId,
	);

	if (!encryptedUserSecretKeyShare) {
		throw new Error('Encrypted user secret key share not found');
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

	await ikaTransaction.requestSign({
		dWallet: dwallet,
		messageApproval,
		verifiedPresignCap,
		hashScheme: hash,
		presign,
		encryptedUserSecretKeyShare,
		message,
		signatureScheme: signatureAlgorithm,
		ikaCoin,
		suiCoin,
	});

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
		options: {
			showEvents: true,
		},
	});

	const signEvent = result.events?.find((event) => event.type.includes('SignRequestEvent'));

	if (!signEvent) {
		throw new Error('Sign event not found');
	}

	const signEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.SignRequestEvent,
	).fromBase64(signEvent.bcs as string);

	return {
		signId: signEventData.event_data.sign_id,
		digest: result.digest,
	};
}

runDKGPresignSign().catch(console.error);
