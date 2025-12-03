import { SuiClient } from '@mysten/sui/client';
import {
	SerialTransactionExecutor,
	Transaction,
	TransactionObjectArgument,
} from '@mysten/sui/transactions';

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

interface SignResult {
	signId: string;
	presignId: string;
	completed: boolean;
	signature?: number[];
	error?: string;
}

export async function runBulkPresignSign() {
	await ikaClient.initialize();

	// Create SerialTransactionExecutor for efficient sequential execution
	const executor = new SerialTransactionExecutor({
		client: suiClient,
		signer: signer,
	});

	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

	// Configuration
	const curve = Curve.ED25519;
	const signatureAlgorithm = SignatureAlgorithm.EdDSA;
	const hash = Hash.SHA512;
	const numberOfPresigns = 100;

	console.log(`\n=== Starting Bulk Presign/Sign Test ===`);
	console.log(`Curve: ${curve}`);
	console.log(`Signature Algorithm: ${signatureAlgorithm}`);
	console.log(`Hash: ${hash}`);
	console.log(`Number of presigns/signs: ${numberOfPresigns}\n`);

	// Step 1: Create encryption keys
	console.log('Step 1: Setting up encryption keys...');
	const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
		new TextEncoder().encode('test seed bulk' + curve + signatureAlgorithm + hash),
		curve,
	);

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
	await executor.executeTransaction(encryptionKeyTx).catch((error) => {
		console.log('The encryption key was already registered');
	});

	// Step 2: Request DKG (create one dWallet)
	console.log('\nStep 2: Requesting DKG (creating dWallet)...');
	const dkgResult = await requestDKG(
		ikaClient,
		executor,
		userShareEncryptionKeys,
		curve,
		latestNetworkEncryptionKey.id,
		ALICE_IKA_COIN_ID,
	);

	console.log(`DKG requested. DWallet ID: ${dkgResult.dwalletId}, Digest: ${dkgResult.digest}`);

	// Step 3: Wait for DWallet to be in AwaitingKeyHolderSignature state
	console.log('\nStep 3: Waiting for DWallet to be in AwaitingKeyHolderSignature state...');
	const dwallet = await ikaClient.getDWalletInParticularState(
		dkgResult.dwalletId,
		'AwaitingKeyHolderSignature',
		{
			timeout: 60000,
			interval: 2000,
		},
	);

	console.log(`DWallet is now in ${dwallet.state.$kind} state, Cap ID: ${dwallet.dwallet_cap_id}`);

	// Step 4: Accept encrypted user share and activate dwallet
	console.log('\nStep 4: Accepting encrypted user share...');
	await acceptEncryptedUserShare(
		ikaClient,
		executor,
		userShareEncryptionKeys,
		dwallet,
		dkgResult.encryptedUserSecretKeyShareId,
		dkgResult.userPublicOutput,
	);

	console.log('Encrypted user share accepted');

	// Step 5: Wait for dwallet to become Active
	console.log('\nStep 5: Waiting for dwallet to become Active...');
	const activeDWallet = await ikaClient.getDWalletInParticularState(dkgResult.dwalletId, 'Active', {
		timeout: 60000,
		interval: 2000,
	});

	console.log(`DWallet is now Active`);

	// Step 6: Create 100 presigns in a single transaction
	console.log(`\nStep 6: Creating ${numberOfPresigns} presigns in a single transaction...`);

	const presignTx = new Transaction();
	presignTx.setSender(signerAddress);
	presignTx.setGasBudget(10_000_000_000); // Higher budget for batch operation

	const ikaTransactionForPresigns = new IkaTransaction({
		ikaClient,
		transaction: presignTx,
	});

	// Create all presign requests in the same transaction
	const presignCaps: TransactionObjectArgument[] = [];
	for (let i = 0; i < numberOfPresigns; i++) {
		const ikaCoin = presignTx.object(ALICE_IKA_COIN_ID);
		const suiCoin = presignTx.gas;

		const unverifiedPresignCap = ikaTransactionForPresigns.requestGlobalPresign({
			curve,
			signatureAlgorithm,
			dwalletNetworkEncryptionKeyId: latestNetworkEncryptionKey.id,
			ikaCoin,
			suiCoin,
		});

		presignCaps.push(unverifiedPresignCap);
	}

	// Transfer all presign caps to signer
	presignTx.transferObjects(presignCaps, signerAddress);

	console.log(`Executing single transaction with ${numberOfPresigns} presigns...`);
	const presignResult = await executor.executeTransaction(presignTx, {
		showEvents: true,
	});

	// Extract all presign IDs from events
	const presignEvents =
		presignResult.data.events?.filter((event) => event.type.includes('PresignRequestEvent')) || [];

	const presignResults: Array<{ presignId: string; digest: string; index: number }> = [];

	for (let i = 0; i < presignEvents.length; i++) {
		const presignEventData = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.PresignRequestEvent,
		).fromBase64(presignEvents[i].bcs as string);

		presignResults.push({
			presignId: presignEventData.event_data.presign_id,
			digest: presignResult.digest,
			index: i,
		});
	}

	console.log(
		`\nSuccessfully created ${presignResults.length} presigns in single transaction (Digest: ${presignResult.digest})`,
	);

	// Step 7: Wait for all presigns to complete in parallel
	console.log(`\nStep 7: Waiting for all presigns to complete...`);

	const presignPromises = presignResults.map((result, index) =>
		ikaClient
			.getPresignInParticularState(result.presignId, 'Completed', {
				timeout: 180000,
				interval: 5000,
			})
			.then((presign) => ({ presign, index, error: null }))
			.catch((error) => ({
				presign: null,
				index,
				error: (error as Error).message,
			})),
	);

	const presignSettledResults = await Promise.all(presignPromises);
	const completedPresigns = presignSettledResults
		.filter((r) => r.presign !== null)
		.map((r) => r.presign);

	const failedPresignCount = presignSettledResults.filter((r) => r.error !== null).length;
	if (failedPresignCount > 0) {
		console.log(`\nFailed to complete ${failedPresignCount} presigns`);
		console.log(presignSettledResults.filter((r) => r.error !== null));
	}

	console.log(`\nSuccessfully completed ${completedPresigns.length} presigns`);

	// Step 8: Create 100 signs in a single transaction
	console.log(`\nStep 8: Creating ${completedPresigns.length} signs in a single transaction...`);
	const message = new TextEncoder().encode('test message for sign');

	// Get encrypted user secret key share once
	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		dkgResult.encryptedUserSecretKeyShareId,
	);

	if (!encryptedUserSecretKeyShare) {
		throw new Error('Encrypted user secret key share not found');
	}

	// Execute each sign request in a separate transaction
	const signRequestPromises = completedPresigns.map(async (presign, i) => {
		const signTx = new Transaction();
		signTx.setSender(signerAddress);
		signTx.setGasBudget(1_000_000_000);

		const ikaTransactionForSigns = new IkaTransaction({
			ikaClient,
			transaction: signTx,
			userShareEncryptionKeys,
		});

		const ikaCoin = signTx.object(ALICE_IKA_COIN_ID);
		const suiCoin = signTx.gas;

		const messageApproval = ikaTransactionForSigns.approveMessage({
			dWalletCap: (activeDWallet as ZeroTrustDWallet).dwallet_cap_id,
			curve,
			signatureAlgorithm,
			hashScheme: hash,
			message,
		});

		const verifiedPresignCap = ikaTransactionForSigns.verifyPresignCap({
			presign,
		});

		console.log(`Requesting sign ${i + 1} of ${completedPresigns.length}...`);

		await ikaTransactionForSigns.requestSign({
			dWallet: activeDWallet as ZeroTrustDWallet,
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

		console.log(`Executing sign transaction ${i + 1} of ${completedPresigns.length}...`);
		const signResult = await executor
			.executeTransaction(signTx, {
				showEvents: true,
			})
			.catch((error) => {
				console.error(`Error executing sign transaction ${i + 1}: ${(error as Error).message}`);
				return null;
			});

		console.log(`Sign ${i + 1} transaction executed (Digest: ${signResult.digest})`);

		return signResult;
	});

	const signTransactionResults = await Promise.all(signRequestPromises);

	// Extract all sign IDs from events across all transactions
	const signResults: SignResult[] = [];

	for (let i = 0; i < signTransactionResults.length; i++) {
		const signResult = signTransactionResults[i];
		const signEvents =
			signResult.data.events?.filter((event) => event.type.includes('SignRequestEvent')) || [];

		if (signEvents.length > 0) {
			const signEventData = SessionsManagerModule.DWalletSessionEvent(
				CoordinatorInnerModule.SignRequestEvent,
			).fromBase64(signEvents[0].bcs as string);

			signResults.push({
				signId: signEventData.event_data.sign_id,
				presignId: presignResults[i]?.presignId || '',
				completed: false,
			});
		} else {
			signResults.push({
				signId: '',
				presignId: presignResults[i]?.presignId || '',
				completed: false,
				error: 'No sign event found in transaction',
			});
		}
	}

	console.log(
		`\nSuccessfully created ${signResults.length} signs in ${signTransactionResults.length} separate transactions`,
	);

	// Step 9: Check if all signs are completed in parallel
	console.log(`\nStep 9: Checking completion status of all signs...`);

	const signPromises = signResults.map((result) => {
		if (!result.signId) {
			return Promise.resolve({
				signId: result.signId,
				presignId: result.presignId,
				completed: false,
				signature: undefined as number[] | undefined,
				error: result.error,
			});
		}

		return ikaClient
			.getSignInParticularState(result.signId, curve, signatureAlgorithm, 'Completed', {
				timeout: 60000,
				interval: 2000,
			})
			.then((sign) => ({
				signId: result.signId,
				presignId: result.presignId,
				completed: sign.state.$kind === 'Completed',
				signature: sign.state.$kind === 'Completed' ? sign.state.Completed?.signature : undefined,
				error: undefined as string | undefined,
			}))
			.catch((error) => ({
				signId: result.signId,
				presignId: result.presignId,
				completed: false,
				signature: undefined as number[] | undefined,
				error: (error as Error).message,
			}));
	});

	const completedSigns = await Promise.all(signPromises);

	// Step 10: Summary
	console.log(`\n=== Summary ===`);
	console.log(`Total presigns created: ${presignResults.length}`);
	console.log(`Total presigns completed: ${completedPresigns.length}`);
	console.log(`Total signs created: ${signResults.filter((r) => r.signId).length}`);
	console.log(`Total signs completed: ${completedSigns.filter((r) => r.completed).length}`);
	console.log(`Total signs with errors: ${completedSigns.filter((r) => r.error).length}`);

	console.log(`\n=== Detailed Results ===`);
	console.dir(completedSigns, { depth: null });
}

async function requestDKG(
	ikaClient: IkaClient,
	executor: SerialTransactionExecutor,
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

	const result = await executor.executeTransaction(tx, {
		showEvents: true,
	});

	const dkgEvent = result.data.events?.find((event) =>
		event.type.includes('DWalletDKGRequestEvent'),
	);

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

async function acceptEncryptedUserShare(
	ikaClient: IkaClient,
	executor: SerialTransactionExecutor,
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

	const result = await executor.executeTransaction(tx);

	return result.digest;
}

runBulkPresignSign().catch(console.error);
