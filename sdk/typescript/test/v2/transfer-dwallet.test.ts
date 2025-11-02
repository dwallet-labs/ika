import { Transaction } from '@mysten/sui/transactions';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { describe, expect, it } from 'vitest';

import {
	CoordinatorInnerModule,
	Curve,
	Hash,
	IkaClient,
	Presign,
	publicKeyFromDWalletOutput,
	SessionsManagerModule,
	SignatureAlgorithm,
	ZeroTrustDWallet,
} from '../../src';
import { EncryptedUserSecretKeyShare } from '../../src/client/types';
import { UserShareEncryptionKeys } from '../../src/client/user-share-encryption-keys';
import { testPresign } from '../helpers/dwallet-test-helpers';
import {
	createEmptyTestIkaToken,
	createTestIkaClient,
	createTestIkaTransaction,
	createTestMessage,
	createTestSuiClient,
	delay,
	destroyEmptyTestIkaToken,
	executeTestTransaction,
	generateTestKeypair,
	requestTestFaucetFunds,
	retryUntil,
} from '../helpers/test-utils';
import {
	acceptUserShareAndActivate,
	executeDKGRequest,
	prepareDKG,
	setupDKGTest,
	waitForDWalletAwaitingSignature,
} from './helpers';

/**
 * Compute hash based on the hash scheme
 */
function computeHash(message: Uint8Array, hashScheme: Hash): Uint8Array {
	switch (hashScheme) {
		case Hash.KECCAK256:
			return keccak_256(message);
		case Hash.SHA256:
			return sha256(message);
		case Hash.DoubleSHA256:
			return sha256(sha256(message));
		case Hash.SHA512:
			return sha512(message);
		case Hash.Merlin:
			throw new Error('Merlin hash computation not supported client-side');
		default:
			throw new Error(`Unsupported hash scheme: ${hashScheme}`);
	}
}

/**
 * Verify signature based on the curve and hash
 */
function verifySignature(
	signature: Uint8Array,
	hash: Uint8Array,
	publicKey: Uint8Array,
	signatureAlgorithm: SignatureAlgorithm,
	message?: Uint8Array,
): boolean {
	switch (signatureAlgorithm) {
		case SignatureAlgorithm.ECDSASecp256k1:
			return secp256k1.verify(signature, hash, publicKey, { prehash: false });
		case SignatureAlgorithm.Taproot:
			return schnorr.verify(signature, hash, publicKey.slice(1));
		case SignatureAlgorithm.ECDSASecp256r1:
			return p256.verify(signature, hash, publicKey, { prehash: false });
		case SignatureAlgorithm.EdDSA:
			if (!message) {
				throw new Error('Message is required for EdDSA');
			}
			return ed25519.verify(signature, message, publicKey);
		case SignatureAlgorithm.SchnorrkelSubstrate:
			return true; // Skip client-side verification for Schnorrkel
		default:
			throw new Error(`Unsupported signature algorithm: ${signatureAlgorithm}`);
	}
}

/**
 * Setup Bob's environment
 */
async function setupBob(
	testName: string,
	curve: Curve,
): Promise<{
	bobUserShareEncryptionKeys: UserShareEncryptionKeys;
	bobSignerAddress: string;
}> {
	const { userShareEncryptionKeys: bobUserShareEncryptionKeys, signerAddress: bobSignerAddress } =
		await generateTestKeypair(`${testName}-bob`, curve);

	await requestTestFaucetFunds(bobSignerAddress);

	return {
		bobUserShareEncryptionKeys,
		bobSignerAddress,
	};
}

/**
 * Alice re-encrypts and transfers her user share to Bob
 */
async function aliceTransferShareToBob(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet,
	aliceEncryptedUserSecretKeyShareId: string,
	aliceUserShareEncryptionKeys: UserShareEncryptionKeys,
	bobEncryptionKeyAddress: string,
	testName: string,
	bobSignerAddress,
): Promise<{
	bobEncryptedUserSecretKeyShareId: string;
	aliceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare;
}> {
	const suiClient = createTestSuiClient();

	// Get Alice's encrypted user secret key share
	const aliceEncryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		aliceEncryptedUserSecretKeyShareId,
	);
	expect(aliceEncryptedUserSecretKeyShare).toBeDefined();

	// Alice creates transaction to re-encrypt her share for Bob
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		transaction,
		aliceUserShareEncryptionKeys,
	);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestReEncryptUserShareFor({
		dWallet: activeDWallet,
		destinationEncryptionKeyAddress: bobEncryptionKeyAddress,
		sourceEncryptedUserSecretKeyShare: aliceEncryptedUserSecretKeyShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	transaction.transferObjects([activeDWallet.dwallet_cap_id], bobSignerAddress);

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	const result = await executeTestTransaction(suiClient, transaction, testName);

	// Find the re-encrypt event
	const reEncryptEvent = result.events?.find((event) =>
		event.type.includes('EncryptedShareVerificationRequestEvent'),
	);
	expect(reEncryptEvent).toBeDefined();

	const parsedReEncryptEvent = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.EncryptedShareVerificationRequestEvent,
	).fromBase64(reEncryptEvent?.bcs as string);

	expect(parsedReEncryptEvent).toBeDefined();

	const bobEncryptedUserSecretKeyShareId =
		parsedReEncryptEvent.event_data.encrypted_user_secret_key_share_id;
	expect(bobEncryptedUserSecretKeyShareId).toBeDefined();

	// Wait for Bob's encrypted share to be available
	const bobEncryptedUserSecretKeyShare = await retryUntil(
		() =>
			ikaClient.getEncryptedUserSecretKeyShareInParticularState(
				bobEncryptedUserSecretKeyShareId,
				'NetworkVerificationCompleted',
			),
		(share) => share !== null,
		30,
		1000,
	);

	expect(bobEncryptedUserSecretKeyShare).toBeDefined();

	return {
		bobEncryptedUserSecretKeyShareId,
		aliceEncryptedUserSecretKeyShare,
	};
}

/**
 * Bob accepts the transferred encrypted user share
 */
async function bobAcceptTransferredShare(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet,
	aliceEncryptedUserSecretKeyShare: EncryptedUserSecretKeyShare,
	bobEncryptedUserSecretKeyShareId: string,
	aliceUserShareEncryptionKeys: UserShareEncryptionKeys,
	bobUserShareEncryptionKeys: UserShareEncryptionKeys,
	testName: string,
): Promise<void> {
	const suiClient = createTestSuiClient();

	// Get Bob's encrypted user secret key share
	const bobEncryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		bobEncryptedUserSecretKeyShareId,
	);
	expect(bobEncryptedUserSecretKeyShare).toBeDefined();

	// Get Alice's encryption key
	const aliceEncryptionKey = await ikaClient.getActiveEncryptionKey(
		aliceEncryptedUserSecretKeyShare.encryption_key_address,
	);
	expect(aliceEncryptionKey).toBeDefined();

	// Bob creates transaction to accept the transferred share
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		transaction,
		bobUserShareEncryptionKeys,
	);

	await ikaTransaction.acceptEncryptedUserShare({
		dWallet: activeDWallet,
		sourceEncryptionKey: aliceEncryptionKey,
		sourceEncryptedUserSecretKeyShare: aliceEncryptedUserSecretKeyShare,
		destinationEncryptedUserSecretKeyShare: bobEncryptedUserSecretKeyShare,
	});

	await executeTestTransaction(suiClient, transaction, testName);
}

/**
 * Request presign and wait for completion
 */
async function requestAndWaitForPresign(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	signerAddress: string,
	testName: string,
): Promise<Presign> {
	const suiClient = createTestSuiClient();

	const presignRequestEvent = await testPresign(
		ikaClient,
		suiClient,
		activeDWallet,
		curve,
		signatureAlgorithm,
		signerAddress,
		testName,
	);

	expect(presignRequestEvent).toBeDefined();
	expect(presignRequestEvent.event_data.presign_id).toBeDefined();

	const presignObject = await retryUntil(
		() =>
			ikaClient.getPresignInParticularState(presignRequestEvent.event_data.presign_id, 'Completed'),
		(presign) => presign !== null,
		30,
		2000,
	);

	expect(presignObject).toBeDefined();
	expect(presignObject.state.$kind).toBe('Completed');

	return presignObject;
}

/**
 * Bob signs with the transferred DWallet and verifies
 */
async function bobSignAndVerify(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet,
	bobUserShareEncryptionKeys: UserShareEncryptionKeys,
	bobEncryptedUserSecretKeyShareId: string,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	curve: Curve,
	testName: string,
): Promise<void> {
	const suiClient = createTestSuiClient();

	// Get Bob's encrypted user secret key share
	const bobEncryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		bobEncryptedUserSecretKeyShareId,
	);
	expect(bobEncryptedUserSecretKeyShare).toBeDefined();

	// Bob creates a transaction to sign the message
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(
		ikaClient,
		transaction,
		bobUserShareEncryptionKeys,
	);

	const messageApproval = ikaTransaction.approveMessage({
		dWalletCap: activeDWallet.dwallet_cap_id,
		curve,
		signatureAlgorithm,
		hashScheme,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	await ikaTransaction.requestSign({
		dWallet: activeDWallet,
		messageApproval,
		verifiedPresignCap,
		hashScheme,
		presign,
		encryptedUserSecretKeyShare: bobEncryptedUserSecretKeyShare,
		message,
		signatureScheme: signatureAlgorithm,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	// Execute the signing transaction
	const result = await executeTestTransaction(suiClient, transaction, testName);

	const signEvent = result.events?.find((event) => event.type.includes('SignRequestEvent'));
	expect(signEvent).toBeDefined();

	const signEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.SignRequestEvent,
	).fromBase64(signEvent?.bcs as string);

	expect(signEventData).toBeDefined();

	const sign = await ikaClient.getSignInParticularState(
		signEventData.event_data.sign_id,
		curve,
		signatureAlgorithm,
		'Completed',
		{ timeout: 60000, interval: 1000 },
	);

	const dWallet = await ikaClient.getDWalletInParticularState(
		signEventData.event_data.dwallet_id,
		'Active',
	);

	expect(sign).toBeDefined();
	expect(sign.state.$kind).toBe('Completed');
	expect(sign.state.Completed?.signature).toBeDefined();

	const signature = Uint8Array.from(sign.state.Completed?.signature ?? []);

	const pkOutput = await publicKeyFromDWalletOutput(
		curve,
		Uint8Array.from(dWallet.state.Active?.public_output ?? []),
	);

	// Verify signature only for algorithms where we have client-side verification
	if (hashScheme !== Hash.Merlin) {
		const expectedHash = computeHash(message, hashScheme);

		const verified = verifySignature(
			signature,
			expectedHash,
			pkOutput,
			signatureAlgorithm,
			message,
		);

		expect(verified).toBe(true);
	}
}

/**
 * Test complete transfer flow: Alice creates DWallet, transfers to Bob, Bob signs
 */
async function testDWalletTransfer(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	testNameSuffix: string,
) {
	const testName = `transfer-${testNameSuffix}`;

	// Setup Alice's DKG test environment
	const aliceSetup = await setupDKGTest(`${testName}-alice`, curve);
	const {
		ikaClient,
		userShareEncryptionKeys: aliceUserShareEncryptionKeys,
		signerAddress: aliceSignerAddress,
	} = aliceSetup;

	// Alice prepares DKG
	const dkgPrepare = await prepareDKG(
		ikaClient,
		curve,
		aliceUserShareEncryptionKeys,
		aliceSignerAddress,
	);

	// Alice executes DKG request (creates zero trust wallet with encrypted share)
	const dkgResult = await executeDKGRequest(aliceSetup, dkgPrepare, curve);

	// Setup Bob's environment while Alice's DKG is processing
	const { bobUserShareEncryptionKeys, bobSignerAddress } = await setupBob(testName, curve);

	// Wait for DWallet to be in AwaitingKeyHolderSignature state
	const awaitingDWallet = await waitForDWalletAwaitingSignature(ikaClient, dkgResult.dWalletID);

	// Alice accepts user share and activates the DWallet
	const activeDWallet = await acceptUserShareAndActivate(
		aliceSetup,
		dkgResult.dWalletID,
		dkgResult.encryptedUserSecretKeyShareId,
		dkgResult.userPublicOutput,
		awaitingDWallet,
	);

	// Bob registers his encryption key
	const bobRegisterTransaction = new Transaction();
	const bobRegisterIkaTransaction = createTestIkaTransaction(
		ikaClient,
		bobRegisterTransaction,
		bobUserShareEncryptionKeys,
	);

	await bobRegisterIkaTransaction.registerEncryptionKey({ curve });

	const suiClient = createTestSuiClient();
	await executeTestTransaction(suiClient, bobRegisterTransaction, `${testName}-bob`);

	// Alice transfers her user share to Bob by re-encrypting
	const { bobEncryptedUserSecretKeyShareId, aliceEncryptedUserSecretKeyShare } =
		await aliceTransferShareToBob(
			ikaClient,
			activeDWallet,
			dkgResult.encryptedUserSecretKeyShareId,
			aliceUserShareEncryptionKeys,
			bobUserShareEncryptionKeys.getSuiAddress(),
			`${testName}-alice`,
			bobSignerAddress,
		);

	// Bob accepts the transferred encrypted user share
	await bobAcceptTransferredShare(
		ikaClient,
		activeDWallet,
		aliceEncryptedUserSecretKeyShare,
		bobEncryptedUserSecretKeyShareId,
		aliceUserShareEncryptionKeys,
		bobUserShareEncryptionKeys,
		`${testName}-bob`,
	);

	await delay(5); //

	// Request presign (Bob can use the DWallet now)
	const presign = await requestAndWaitForPresign(
		ikaClient,
		activeDWallet,
		curve,
		signatureAlgorithm,
		bobSignerAddress,
		`${testName}-bob`,
	);

	// Bob signs with the transferred DWallet and verifies the signature
	const message = createTestMessage(`${testName}-bob-sign`);

	await bobSignAndVerify(
		ikaClient,
		activeDWallet,
		bobUserShareEncryptionKeys,
		bobEncryptedUserSecretKeyShareId,
		presign,
		message,
		hash,
		signatureAlgorithm,
		curve,
		`${testName}-bob`,
	);
}

describe('DWallet Transfer from Alice to Bob', () => {
	describe('ECDSASecp256k1 on SECP256K1', () => {
		it('should transfer DWallet from Alice to Bob and Bob should sign with KECCAK256', async () => {
			await testDWalletTransfer(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.KECCAK256,
				'ecdsa-secp256k1-keccak256',
			);
		});

		it('should transfer DWallet from Alice to Bob and Bob should sign with SHA256', async () => {
			await testDWalletTransfer(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.SHA256,
				'ecdsa-secp256k1-sha256',
			);
		});

		it('should transfer DWallet from Alice to Bob and Bob should sign with DoubleSHA256', async () => {
			await testDWalletTransfer(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.DoubleSHA256,
				'ecdsa-secp256k1-double-sha256',
			);
		});
	});

	describe('Taproot on SECP256K1', () => {
		it('should transfer DWallet from Alice to Bob and Bob should sign with SHA256', async () => {
			await testDWalletTransfer(
				Curve.SECP256K1,
				SignatureAlgorithm.Taproot,
				Hash.SHA256,
				'taproot-sha256',
			);
		});
	});

	describe('ECDSASecp256r1 on SECP256R1', () => {
		it('should transfer DWallet from Alice to Bob and Bob should sign with SHA256', async () => {
			await testDWalletTransfer(
				Curve.SECP256R1,
				SignatureAlgorithm.ECDSASecp256r1,
				Hash.SHA256,
				'ecdsa-secp256r1-sha256',
			);
		});
	});

	describe('EdDSA on ED25519', () => {
		it('should transfer DWallet from Alice to Bob and Bob should sign with SHA512', async () => {
			await testDWalletTransfer(
				Curve.ED25519,
				SignatureAlgorithm.EdDSA,
				Hash.SHA512,
				'eddsa-sha512',
			);
		});
	});

	describe('SchnorrkelSubstrate on RISTRETTO', () => {
		it('should transfer DWallet from Alice to Bob and Bob should sign with Merlin', async () => {
			await testDWalletTransfer(
				Curve.RISTRETTO,
				SignatureAlgorithm.SchnorrkelSubstrate,
				Hash.Merlin,
				'schnorrkel-merlin',
			);
		});
	});
});
