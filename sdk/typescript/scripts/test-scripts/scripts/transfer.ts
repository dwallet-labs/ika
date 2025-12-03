import { SuiClient } from '@mysten/sui/client';
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
	EncryptedUserSecretKeyShare,
	Hash,
	Presign,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../../src/client/types';
import { UserShareEncryptionKeys } from '../../../src/client/user-share-encryption-keys';
import {
	alice,
	ALICE_IKA_COIN_ID,
	aliceAddress,
	bob,
	BOB_IKA_COIN_ID,
	bobAddress,
	ikaClient,
	suiClient,
} from './const';

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
	activateDigest: string;
	presignId: string;
	presignDigest: string;
	transferDigest: string;
	acceptTransferDigest: string;
	signId: string;
	signDigest: string;
	signature?: number[];
	error?: string;
}

export async function runTransferBenchmark() {
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

		// Setup Alice's encryption keys
		const aliceUserShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('alice seed' + curve),
			curve,
		);

		// Setup Bob's encryption keys
		const bobUserShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('bob seed' + curve),
			curve,
		);

		// Register Alice's encryption key once per curve
		console.log(`Registering Alice's encryption key for curve ${curve}...`);
		const aliceEncryptionKeyTx = new Transaction();
		aliceEncryptionKeyTx.setSender(aliceAddress);
		aliceEncryptionKeyTx.setGasBudget(1_000_000_000);
		const aliceIkaTransactionForEncryption = new IkaTransaction({
			ikaClient,
			transaction: aliceEncryptionKeyTx,
			userShareEncryptionKeys: aliceUserShareEncryptionKeys,
		});

		await aliceIkaTransactionForEncryption.registerEncryptionKey({
			curve,
		});

		await suiClient
			.signAndExecuteTransaction({
				transaction: aliceEncryptionKeyTx,
				signer: alice,
			})
			.catch((error) => {
				console.log("Alice's encryption key was already registered");
			});

		// Register Bob's encryption key once per curve
		console.log(`Registering Bob's encryption key for curve ${curve}...`);
		const bobEncryptionKeyTx = new Transaction();
		bobEncryptionKeyTx.setSender(bobAddress);
		bobEncryptionKeyTx.setGasBudget(1_000_000_000);
		const bobIkaTransactionForEncryption = new IkaTransaction({
			ikaClient,
			transaction: bobEncryptionKeyTx,
			userShareEncryptionKeys: bobUserShareEncryptionKeys,
		});

		await bobIkaTransactionForEncryption.registerEncryptionKey({
			curve,
		});

		await suiClient
			.signAndExecuteTransaction({
				transaction: bobEncryptionKeyTx,
				signer: bob,
			})
			.catch((error) => {
				console.log("Bob's encryption key was already registered");
			});

		// Process each combination for this curve
		for (const combo of combos) {
			console.log(
				`\n--- Processing: ${combo.curve} - ${combo.signatureAlgorithm} - ${combo.hash} ---`,
			);

			try {
				// Step 1: Alice requests DKG
				console.log('Step 1: Alice requesting DKG...');
				const dkgResult = await aliceRequestDKG(
					ikaClient,
					suiClient,
					aliceUserShareEncryptionKeys,
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

				console.log(`DWallet is now in ${dwallet.state.$kind} state`);

				// Step 3: Alice accepts encrypted user share and activates dwallet
				console.log('Step 3: Alice accepting encrypted user share...');
				const activateDigest = await aliceAcceptEncryptedUserShare(
					ikaClient,
					suiClient,
					aliceUserShareEncryptionKeys,
					dwallet,
					dkgResult.encryptedUserSecretKeyShareId,
					dkgResult.userPublicOutput,
				);

				console.log(`Encrypted user share accepted. Digest: ${activateDigest}`);

				// Step 4: Wait for dwallet to become Active
				console.log('Step 4: Waiting for dwallet to become Active...');
				const activeDWallet = await ikaClient.getDWalletInParticularState(
					dkgResult.dwalletId,
					'Active',
					{
						timeout: 60000,
						interval: 2000,
					},
				);

				console.log(`DWallet is now Active`);

				// Step 5: Request global presign
				console.log('Step 5: Requesting global presign...');
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

				// Step 6: Wait for presign to complete
				console.log('Step 6: Waiting for presign to complete...');
				const presign = await ikaClient.getPresignInParticularState(
					presignResult.presignId,
					'Completed',
					{
						timeout: 60000,
						interval: 2000,
					},
				);

				console.log(`Presign completed with state: ${presign.state.$kind}`);

				// Step 7: Alice re-encrypts and transfers her user share to Bob, and transfers dwallet cap
				console.log('Step 7: Alice transferring share and dwallet cap to Bob...');
				const transferResult = await aliceTransferShareAndCapToBob(
					ikaClient,
					suiClient,
					aliceUserShareEncryptionKeys,
					activeDWallet as ZeroTrustDWallet,
					dkgResult.encryptedUserSecretKeyShareId,
					bobUserShareEncryptionKeys.getSuiAddress(),
					ALICE_IKA_COIN_ID,
				);

				console.log(
					`Transfer completed. Bob's encrypted share ID: ${transferResult.bobEncryptedUserSecretKeyShareId}, Digest: ${transferResult.digest}`,
				);

				// Step 8: Wait for Bob's encrypted share to be verified
				console.log("Step 8: Waiting for Bob's encrypted share to be verified...");
				const bobEncryptedUserSecretKeyShare =
					await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
						transferResult.bobEncryptedUserSecretKeyShareId,
						'NetworkVerificationCompleted',
						{
							timeout: 60000,
							interval: 2000,
						},
					);

				console.log(`Bob's encrypted share verified`);

				// Step 9: Bob accepts the transferred encrypted user share
				console.log('Step 9: Bob accepting transferred share...');
				const acceptTransferDigest = await bobAcceptTransferredShare(
					ikaClient,
					suiClient,
					bobUserShareEncryptionKeys,
					activeDWallet as ZeroTrustDWallet,
					transferResult.aliceEncryptedUserSecretKeyShare,
					bobEncryptedUserSecretKeyShare,
					aliceUserShareEncryptionKeys.getSuiAddress(),
				);

				console.log(`Bob accepted transferred share. Digest: ${acceptTransferDigest}`);

				// Step 10: Bob signs with the transferred DWallet
				console.log('Step 10: Bob requesting sign with transferred dwallet...');
				const message = new TextEncoder().encode('test message for transfer sign');
				const signResult = await bobRequestSign(
					ikaClient,
					suiClient,
					bobUserShareEncryptionKeys,
					activeDWallet as ZeroTrustDWallet,
					presign,
					transferResult.bobEncryptedUserSecretKeyShareId,
					message,
					combo.curve,
					combo.signatureAlgorithm,
					combo.hash,
					BOB_IKA_COIN_ID,
				);

				console.log(`Sign requested. Sign ID: ${signResult.signId}, Digest: ${signResult.digest}`);

				// Step 11: Wait for sign to complete
				console.log('Step 11: Waiting for sign to complete...');
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
					activateDigest,
					presignId: presignResult.presignId,
					presignDigest: presignResult.digest,
					transferDigest: transferResult.digest,
					acceptTransferDigest,
					signId: signResult.signId,
					signDigest: signResult.digest,
					signature: sign.state.$kind === 'Completed' ? sign.state.Completed?.signature : undefined,
				});

				console.log('✅ Transfer completed successfully!');
			} catch (error) {
				console.error(`❌ Error processing combination: ${(error as Error).message}`);
				results.push({
					curve: combo.curve,
					signatureAlgorithm: combo.signatureAlgorithm,
					hash: combo.hash,
					dwalletId: '',
					dkgDigest: '',
					activateDigest: '',
					presignId: '',
					presignDigest: '',
					transferDigest: '',
					acceptTransferDigest: '',
					signId: '',
					signDigest: '',
					error: (error as Error).message,
				});
			}
		}
	}

	console.log('\n=== All Transfer Benchmarks Completed ===');
	console.dir(results, { depth: null });
}

async function aliceRequestDKG(
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
		aliceAddress,
	);

	const tx = new Transaction();
	tx.setSender(aliceAddress);
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

	tx.transferObjects([dWalletCap], aliceAddress);

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: alice,
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

async function aliceAcceptEncryptedUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: DWallet,
	encryptedUserSecretKeyShareId: string,
	userPublicOutput: Uint8Array,
): Promise<string> {
	const tx = new Transaction();
	tx.setSender(aliceAddress);
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
		signer: alice,
	});

	return result.digest;
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
	tx.setSender(aliceAddress);
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

	// Transfer presign cap to Bob since he will be the one signing
	tx.transferObjects([unverifiedPresignCap], bobAddress);

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: alice,
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

async function aliceTransferShareAndCapToBob(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	aliceUserShareEncryptionKeys: UserShareEncryptionKeys,
	activeDWallet: ZeroTrustDWallet,
	aliceEncryptedUserSecretKeyShareId: string,
	bobEncryptionKeyAddress: string,
	ikaCoinId: string,
): Promise<{
	bobEncryptedUserSecretKeyShareId: string;
	aliceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
	digest: string;
}> {
	// Get Alice's encrypted user secret key share
	const aliceEncryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		aliceEncryptedUserSecretKeyShareId,
	);

	if (!aliceEncryptedUserSecretKeyShare) {
		throw new Error('Alice encrypted user secret key share not found');
	}

	// Alice creates transaction to re-encrypt her share for Bob
	const tx = new Transaction();
	tx.setSender(aliceAddress);
	tx.setGasBudget(1_000_000_000);
	const ikaCoin = tx.object(ikaCoinId);
	const suiCoin = tx.gas;

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction: tx,
		userShareEncryptionKeys: aliceUserShareEncryptionKeys,
	});

	await ikaTransaction.requestReEncryptUserShareFor({
		dWallet: activeDWallet,
		destinationEncryptionKeyAddress: bobEncryptionKeyAddress,
		sourceEncryptedUserSecretKeyShare: aliceEncryptedUserSecretKeyShare,
		ikaCoin,
		suiCoin,
	});

	// Transfer dwallet cap to Bob
	const dwalletCapObj = tx.object(activeDWallet.dwallet_cap_id);
	tx.transferObjects([dwalletCapObj], bobAddress);

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: alice,
		options: {
			showEvents: true,
		},
	});

	// Find the re-encrypt event
	const reEncryptEvent = result.events?.find((event) =>
		event.type.includes('EncryptedShareVerificationRequestEvent'),
	);

	if (!reEncryptEvent) {
		throw new Error('Re-encrypt event not found');
	}

	const parsedReEncryptEvent = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.EncryptedShareVerificationRequestEvent,
	).fromBase64(reEncryptEvent.bcs as string);

	const bobEncryptedUserSecretKeyShareId =
		parsedReEncryptEvent.event_data.encrypted_user_secret_key_share_id;

	return {
		bobEncryptedUserSecretKeyShareId,
		aliceEncryptedUserSecretKeyShare,
		digest: result.digest,
	};
}

async function bobAcceptTransferredShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	bobUserShareEncryptionKeys: UserShareEncryptionKeys,
	activeDWallet: ZeroTrustDWallet,
	aliceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	bobEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	aliceEncryptionKeyAddress: string,
): Promise<string> {
	// Get Alice's encryption key
	const aliceEncryptionKey = await ikaClient.getActiveEncryptionKey(aliceEncryptionKeyAddress);

	if (!aliceEncryptionKey) {
		throw new Error('Alice encryption key not found');
	}

	// Bob creates transaction to accept the transferred share
	const tx = new Transaction();
	tx.setSender(bobAddress);
	tx.setGasBudget(1_000_000_000);

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction: tx,
		userShareEncryptionKeys: bobUserShareEncryptionKeys,
	});

	await ikaTransaction.acceptEncryptedUserShare({
		dWallet: activeDWallet,
		sourceEncryptionKey: aliceEncryptionKey,
		sourceEncryptedUserSecretKeyShare: aliceEncryptedUserSecretKeyShare,
		destinationEncryptedUserSecretKeyShare: bobEncryptedUserSecretKeyShare,
	});

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: bob,
	});

	return result.digest;
}

async function bobRequestSign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	bobUserShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: ZeroTrustDWallet,
	presign: Presign,
	bobEncryptedUserSecretKeyShareId: string,
	message: Uint8Array,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	ikaCoinId: string,
): Promise<{
	signId: string;
	digest: string;
}> {
	// Wait for Bob's encrypted user secret key share to have a user output signature
	console.log("Waiting for Bob's user output signature to be ready...");
	let bobEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare | null = null;
	const maxRetries = 30;
	const retryInterval = 2000; // 2 seconds

	for (let i = 0; i < maxRetries; i++) {
		bobEncryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
			bobEncryptedUserSecretKeyShareId,
		);

		if (!bobEncryptedUserSecretKeyShare) {
			throw new Error('Bob encrypted user secret key share not found');
		}

		// Check if the share is in KeyHolderSigned state with user_output_signature
		if (
			bobEncryptedUserSecretKeyShare.state.$kind === 'KeyHolderSigned' &&
			bobEncryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature
		) {
			console.log("Bob's user output signature is ready");
			break;
		}

		if (i < maxRetries - 1) {
			console.log(
				`Attempt ${i + 1}/${maxRetries}: User output signature not ready yet (state: ${bobEncryptedUserSecretKeyShare.state.$kind}), waiting...`,
			);
			await new Promise((resolve) => setTimeout(resolve, retryInterval));
		}
	}

	if (
		!bobEncryptedUserSecretKeyShare ||
		bobEncryptedUserSecretKeyShare.state.$kind !== 'KeyHolderSigned' ||
		!bobEncryptedUserSecretKeyShare.state.KeyHolderSigned?.user_output_signature
	) {
		throw new Error("Timed out waiting for Bob's user output signature");
	}

	const tx = new Transaction();
	tx.setSender(bobAddress);
	tx.setGasBudget(1_000_000_000);
	const ikaCoin = tx.object(ikaCoinId);
	const suiCoin = tx.gas;

	const ikaTransaction = new IkaTransaction({
		ikaClient,
		transaction: tx,
		userShareEncryptionKeys: bobUserShareEncryptionKeys,
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
		encryptedUserSecretKeyShare: bobEncryptedUserSecretKeyShare,
		message,
		signatureScheme: signatureAlgorithm,
		ikaCoin,
		suiCoin,
	});

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: bob,
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

runTransferBenchmark().catch(console.error);
