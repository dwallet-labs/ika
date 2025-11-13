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
			// Double SHA256 - hash of hash
			return sha256(sha256(message));
		case Hash.SHA512:
			return sha512(message);
		case Hash.Merlin:
			// Merlin is handled internally by the network for Schnorrkel
			// We don't compute it client-side for verification
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
			// Taproot uses Schnorr signatures on secp256k1
			// For now, we'll use the same verification as ECDSASecp256k1
			// In production, this would need proper Schnorr verification
			// For Taproot, strip the first byte (prefix) of the publicKey
			return schnorr.verify(signature, hash, publicKey.slice(1));
		case SignatureAlgorithm.ECDSASecp256r1:
			return p256.verify(signature, hash, publicKey, { prehash: false });
		case SignatureAlgorithm.EdDSA:
			if (!message) {
				throw new Error('Message is required for EdDSA');
			}

			return ed25519.verify(signature, message, publicKey);
		case SignatureAlgorithm.SchnorrkelSubstrate:
			// Schnorrkel verification would require special handling
			// For now, we'll skip client-side verification for Schnorrkel
			return true;
		default:
			throw new Error(`Unsupported signature algorithm: ${signatureAlgorithm}`);
	}
}

/**
 * Setup and run complete DKG flow, returning all necessary components for signing
 */
async function setupDKGFlow(
	testName: string,
	curve: Curve,
): Promise<{
	ikaClient: IkaClient;
	activeDWallet: ZeroTrustDWallet;
	encryptedUserSecretKeyShareId: string;
	userShareEncryptionKeys: any;
	signerAddress: string;
}> {
	const suiClient = createTestSuiClient();
	const ikaClient = createTestIkaClient(suiClient);
	await ikaClient.initialize();

	const { userShareEncryptionKeys, signerAddress } = await generateTestKeypair(testName, curve);
	await requestTestFaucetFunds(signerAddress);

	// Prepare DKG
	const dkgPrepare = await prepareDKG(ikaClient, curve, userShareEncryptionKeys, signerAddress);

	// Execute DKG request
	const dkgResult = await executeDKGRequest(
		{ suiClient, ikaClient, userShareEncryptionKeys, signerAddress, testName },
		dkgPrepare,
		curve,
	);

	// Wait for DWallet to be in AwaitingKeyHolderSignature state
	const awaitingDWallet = await waitForDWalletAwaitingSignature(ikaClient, dkgResult.dWalletID);

	// Accept user share and activate
	const activeDWallet = await acceptUserShareAndActivate(
		{ suiClient, ikaClient, userShareEncryptionKeys, signerAddress, testName },
		dkgResult.dWalletID,
		dkgResult.encryptedUserSecretKeyShareId,
		dkgResult.userPublicOutput,
		awaitingDWallet,
	);

	return {
		ikaClient,
		activeDWallet,
		encryptedUserSecretKeyShareId: dkgResult.encryptedUserSecretKeyShareId,
		userShareEncryptionKeys,
		signerAddress,
	};
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

	const presignObject = await ikaClient.getPresignInParticularState(
		presignRequestEvent.event_data.presign_id,
		'Completed',
		{ timeout: 600000, interval: 1000 },
	);

	expect(presignObject).toBeDefined();
	expect(presignObject.state.$kind).toBe('Completed');

	return presignObject;
}

/**
 * Sign a message and verify the signature
 */
async function signAndVerify(
	ikaClient: IkaClient,
	activeDWallet: ZeroTrustDWallet,
	userShareEncryptionKeys: any,
	presign: Presign,
	encryptedUserSecretKeyShareId: string,
	message: Uint8Array,
	hashScheme: Hash,
	signatureAlgorithm: SignatureAlgorithm,
	curve: Curve,
	testName: string,
): Promise<void> {
	const suiClient = createTestSuiClient();

	// Get the encrypted user secret key share
	const encryptedUserSecretKeyShare = await ikaClient.getEncryptedUserSecretKeyShare(
		encryptedUserSecretKeyShareId,
	);

	expect(encryptedUserSecretKeyShare).toBeDefined();

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

	await ikaTransaction.requestSign({
		dWallet: activeDWallet,
		messageApproval,
		verifiedPresignCap,
		hashScheme,
		presign,
		encryptedUserSecretKeyShare,
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
		{ timeout: 600000, interval: 1000 },
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
 * Test a specific combination of curve, signature algorithm, and hash
 */
export async function testSignCombination(
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	testNameSuffix: string,
) {
	const testName = `combo-${testNameSuffix}`;

	const {
		ikaClient,
		activeDWallet,
		encryptedUserSecretKeyShareId,
		userShareEncryptionKeys,
		signerAddress,
	} = await setupDKGFlow(testName, curve);

	const presign = await requestAndWaitForPresign(
		ikaClient,
		activeDWallet,
		curve,
		signatureAlgorithm,
		signerAddress,
		testName,
	);

	const message = createTestMessage(testName);

	await signAndVerify(
		ikaClient,
		activeDWallet,
		userShareEncryptionKeys,
		presign,
		encryptedUserSecretKeyShareId,
		message,
		hash,
		signatureAlgorithm,
		curve,
		testName,
	);
}

describe('All Valid Curve-SignatureAlgorithm-Hash Combinations', () => {
	// ECDSASecp256k1 + SECP256K1 combinations (3 tests)
	describe('ECDSASecp256k1 on SECP256K1', () => {
		it('should work with KECCAK256', async () => {
			await testSignCombination(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.KECCAK256,
				'ecdsa-secp256k1-keccak256',
			);
		});

		it('should work with SHA256', async () => {
			await testSignCombination(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.SHA256,
				'ecdsa-secp256k1-sha256',
			);
		});

		it('should work with DoubleSHA256', async () => {
			await testSignCombination(
				Curve.SECP256K1,
				SignatureAlgorithm.ECDSASecp256k1,
				Hash.DoubleSHA256,
				'ecdsa-secp256k1-double-sha256',
			);
		});
	});

	// Taproot + SECP256K1 combinations (1 test)
	describe('Taproot on SECP256K1', () => {
		it('should work with SHA256', async () => {
			await testSignCombination(
				Curve.SECP256K1,
				SignatureAlgorithm.Taproot,
				Hash.SHA256,
				'taproot-sha256',
			);
		});
	});

	// ECDSASecp256r1 + SECP256R1 combinations (1 test)
	describe('ECDSASecp256r1 on SECP256R1', () => {
		it('should work with SHA256', async () => {
			await testSignCombination(
				Curve.SECP256R1,
				SignatureAlgorithm.ECDSASecp256r1,
				Hash.SHA256,
				'ecdsa-secp256r1-sha256',
			);
		});
	});

	// EdDSA + ED25519 combination (1 test)
	describe('EdDSA on ED25519', () => {
		it('should work with SHA512', async () => {
			await testSignCombination(
				Curve.ED25519,
				SignatureAlgorithm.EdDSA,
				Hash.SHA512,
				'eddsa-sha512',
			);
		});
	});

	// SchnorrkelSubstrate + RISTRETTO combination (1 test)
	describe('SchnorrkelSubstrate on RISTRETTO', () => {
		it('should work with Merlin', async () => {
			await testSignCombination(
				Curve.RISTRETTO,
				SignatureAlgorithm.SchnorrkelSubstrate,
				Hash.Merlin,
				'schnorrkel-merlin',
			);
		});
	});
});
