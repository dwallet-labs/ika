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
import { testPresign } from '../helpers/dwallet-test-helpers';
import {
	createEmptyTestIkaToken,
	createTestIkaClient,
	createTestIkaTransaction,
	createTestMessage,
	createTestSuiClient,
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
 * Make DWallet user share public
 */
async function makeDWalletPublic(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet,
	encryptedUserSecretKeyShareId: string,
	userShareEncryptionKeys: any,
	testName: string,
): Promise<ZeroTrustDWallet> {
	const suiClient = createTestSuiClient();

	// Get the encrypted user secret key share
	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareId,
	);
	expect(encryptedUserSecretKeyShare).toBeDefined();

	// Decrypt the user share
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(activeDWallet);
	const { secretShare } = await userShareEncryptionKeys.decryptUserShare(
		activeDWallet,
		encryptedUserSecretKeyShare,
		protocolPublicParameters,
	);

	// Create transaction to make user share public
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

	const emptyIKACoin = createEmptyTestIkaToken(transaction, ikaClient.ikaConfig);

	ikaTransaction.makeDWalletUserSecretKeySharesPublic({
		dWallet: activeDWallet,
		secretShare,
		ikaCoin: emptyIKACoin,
		suiCoin: transaction.gas,
	});

	destroyEmptyTestIkaToken(transaction, ikaClient.ikaConfig, emptyIKACoin);

	await executeTestTransaction(suiClient, transaction, testName);

	// Wait for DWallet to have public shares
	const publicDWallet = await retryUntil(
		() => ikaClient.getDWalletInParticularState(activeDWallet.id.id, 'Active'),
		(wallet) => wallet !== null && wallet.public_user_secret_key_share !== null,
		30,
		2000,
	);

	expect(publicDWallet).toBeDefined();
	expect(publicDWallet.public_user_secret_key_share).toBeDefined();

	return publicDWallet as ZeroTrustDWallet;
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
 * Sign with public user share and verify
 */
async function signWithPublicShareAndVerify(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet,
	userShareEncryptionKeys: any,
	presign: Presign,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	curve: Curve,
	testName: string,
): Promise<void> {
	const suiClient = createTestSuiClient();

	// Verify that DWallet has public shares
	expect(activeDWallet.public_user_secret_key_share).toBeDefined();

	// Create a transaction to sign the message
	const transaction = new Transaction();
	const ikaTransaction = createTestIkaTransaction(ikaClient, transaction, userShareEncryptionKeys);

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

	// Sign without providing encrypted share - should use public shares automatically
	await ikaTransaction.requestSign({
		dWallet: activeDWallet,
		messageApproval,
		verifiedPresignCap,
		hashScheme,
		presign,
		// Not providing encryptedUserSecretKeyShare or secretShare - should use public shares
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
 * Test complete flow: create zero trust wallet, make public, and sign
 */
async function testMakePublicAndSign(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	testNameSuffix: string,
) {
	const testName = `make-public-${testNameSuffix}`;

	// Setup DKG test environment
	const setup = await setupDKGTest(testName, curve);
	const { ikaClient, userShareEncryptionKeys, signerAddress } = setup;

	// Prepare DKG
	const dkgPrepare = await prepareDKG(ikaClient, curve, userShareEncryptionKeys, signerAddress);

	// Execute DKG request (creates zero trust wallet with encrypted share)
	const dkgResult = await executeDKGRequest(setup, dkgPrepare, curve);

	// Wait for DWallet to be in AwaitingKeyHolderSignature state
	const awaitingDWallet = await waitForDWalletAwaitingSignature(ikaClient, dkgResult.dWalletID);

	// Accept user share and activate
	const activeDWallet = await acceptUserShareAndActivate(
		setup,
		dkgResult.dWalletID,
		dkgResult.encryptedUserSecretKeyShareId,
		dkgResult.userPublicOutput,
		awaitingDWallet,
	);

	// Make DWallet user share public
	const publicDWallet = await makeDWalletPublic(
		ikaClient,
		activeDWallet,
		dkgResult.encryptedUserSecretKeyShareId,
		userShareEncryptionKeys,
		testName,
	);

	// Request presign
	const presign = await requestAndWaitForPresign(
		ikaClient,
		publicDWallet,
		curve,
		signatureAlgorithm,
		signerAddress,
		testName,
	);

	// Sign with public share and verify
	const message = createTestMessage(testName);

	await signWithPublicShareAndVerify(
		ikaClient,
		publicDWallet,
		userShareEncryptionKeys,
		presign,
		message,
		hash,
		signatureAlgorithm,
		curve,
		testName,
	);
}

describe('Make User Share Public and Sign', () => {
	describe('ECDSASecp256k1 on SECP256K1', () => {
		it('should create zero trust wallet, make share public, and sign with KECCAK256', async () => {
			await testMakePublicAndSign(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.KECCAK256,
				'ecdsa-secp256k1-keccak256',
			);
		});

		it('should create zero trust wallet, make share public, and sign with SHA256', async () => {
			await testMakePublicAndSign(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.SHA256,
				'ecdsa-secp256k1-sha256',
			);
		});

		it('should create zero trust wallet, make share public, and sign with DoubleSHA256', async () => {
			await testMakePublicAndSign(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.DoubleSHA256,
				'ecdsa-secp256k1-double-sha256',
			);
		});
	});

	describe('Taproot on SECP256K1', () => {
		it('should create zero trust wallet, make share public, and sign with SHA256', async () => {
			await testMakePublicAndSign(
				Curve.SECP256K1,
				SignatureAlgorithm.Taproot,
				Hash.SHA256,
				'taproot-sha256',
			);
		});
	});

	describe('ECDSASecp256r1 on SECP256R1', () => {
		it('should create zero trust wallet, make share public, and sign with SHA256', async () => {
			await testMakePublicAndSign(
				Curve.SECP256R1,
				SignatureAlgorithm.ECDSASecp256r1,
				Hash.SHA256,
				'ecdsa-secp256r1-sha256',
			);
		});
	});

	describe('EdDSA on ED25519', () => {
		it('should create zero trust wallet, make share public, and sign with SHA512', async () => {
			await testMakePublicAndSign(
				Curve.ED25519,
				SignatureAlgorithm.EdDSA,
				Hash.SHA512,
				'eddsa-sha512',
			);
		});
	});

	describe('SchnorrkelSubstrate on RISTRETTO', () => {
		it('should create zero trust wallet, make share public, and sign with Merlin', async () => {
			await testMakePublicAndSign(
				Curve.RISTRETTO,
				SignatureAlgorithm.SchnorrkelSubstrate,
				Hash.Merlin,
				'schnorrkel-merlin',
			);
		});
	});
});
