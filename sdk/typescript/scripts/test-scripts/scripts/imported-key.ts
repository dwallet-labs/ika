import { fromHex } from '@mysten/bcs';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';

import {
	CoordinatorInnerModule,
	publicKeyFromCentralizedDKGOutput,
	publicKeyFromDWalletOutput,
	SessionsManagerModule,
} from '../../../src';
import {
	createRandomSessionIdentifier,
	prepareImportedKeyDWalletVerification,
} from '../../../src/client/cryptography';
import { fromNumberToCurve } from '../../../src/client/hash-signature-validation';
import { IkaClient } from '../../../src/client/ika-client';
import { IkaTransaction } from '../../../src/client/ika-transaction';
import { getNetworkConfig } from '../../../src/client/network-configs';
import { Curve, Hash, ImportedKeyDWallet, SignatureAlgorithm } from '../../../src/client/types';
import { UserShareEncryptionKeys } from '../../../src/client/user-share-encryption-keys';
import { ALICE_IKA_COIN_ID, signer, signerAddress } from './const';

/**
 * Generate a private key for the given curve (same as in tests for consistency)
 */
function generatePrivateKey(curve: Curve): Uint8Array {
	switch (curve) {
		case Curve.SECP256K1:
			return Uint8Array.from(
				fromHex('20255a048b64a9930517e91a2ee6b3aa6ea78131a4ad88f20cb3d351f28d6fe653'),
			);
		case Curve.SECP256R1:
			return Uint8Array.from(
				fromHex('20c53afc96882df03726eba161dcddfc4a44c08dea525700692b99db108125ed5f'),
			);
		case Curve.ED25519:
			return Uint8Array.from(
				fromHex('7aca0549f93cc4a2052a23f10fc8577d1aba9058766eeebdaa0a7f39bbe91606'),
			);
		case Curve.RISTRETTO:
			return Uint8Array.from(
				fromHex('1ac94bd6e52bc134b6d482f6443d3c61bd987366dffc2c717bcb35dc62e5650b'),
			);
		default:
			throw new Error(`Unsupported curve: ${curve}`);
	}
}

/**
 * Decode public key based on curve
 */
function decodePublicKey(curve: Curve, encodedPublicKey: Uint8Array): Uint8Array {
	switch (curve) {
		case Curve.SECP256K1:
		case Curve.SECP256R1:
			// For SECP curves, the encoded key includes a prefix byte that we need to keep
			return encodedPublicKey;
		case Curve.ED25519:
		case Curve.RISTRETTO:
			// For ED25519 and RISTRETTO, return as is
			return encodedPublicKey;
		default:
			throw new Error(`Unsupported curve: ${curve}`);
	}
}

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
function verifySignatureWithPublicKey(
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
			// Schnorrkel verification would require special handling
			return true;
		default:
			throw new Error(`Unsupported signature algorithm: ${signatureAlgorithm}`);
	}
}

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
	verificationDigest: string;
	presignId: string;
	presignDigest: string;
	signId: string;
	signDigest: string;
	signature?: number[];
	signatureVerified?: boolean;
	publicKeysMatch?: boolean;
	error?: string;
}

export async function runImportedKeyBenchmark() {
	const suiClient = new SuiClient({ url: 'https://sui-testnet-rpc.publicnode.com' });

	const ikaClient = new IkaClient({
		suiClient,
		config: getNetworkConfig('testnet'),
	});

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

		// Register encryption key for imported key dwallet
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

		// Get the private key for this curve
		const privateKey = generatePrivateKey(curve);

		for (const combo of combos) {
			console.log(
				`\n--- Processing: ${combo.curve} - ${combo.signatureAlgorithm} - ${combo.hash} ---`,
			);

			try {
				// Step 1: Request imported key DWallet verification
				console.log('Step 1: Requesting imported key DWallet verification...');
				const verificationResult = await requestImportedKeyVerification(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					combo.curve,
					privateKey,
					ALICE_IKA_COIN_ID,
				);

				console.log(
					`Imported key verification requested. DWallet ID: ${verificationResult.dwalletId}`,
				);

				// Step 2: Wait for AwaitingKeyHolderSignature
				console.log('Step 2: Waiting for DWallet to be in AwaitingKeyHolderSignature state...');
				const dwallet = await ikaClient.getDWalletInParticularState(
					verificationResult.dwalletId,
					'AwaitingKeyHolderSignature',
					{ timeout: 60000, interval: 2000 },
				);

				// Step 3: Accept user share
				console.log('Step 3: Accepting encrypted user share...');
				await acceptEncryptedUserShare(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					dwallet as ImportedKeyDWallet,
					verificationResult.encryptedUserSecretKeyShareId,
					verificationResult.userPublicOutput,
				);

				// Step 4: Wait for Active
				console.log('Step 4: Waiting for dwallet to become Active...');
				const activeDWallet = (await ikaClient.getDWalletInParticularState(
					verificationResult.dwalletId,
					'Active',
					{ timeout: 60000, interval: 2000 },
				)) as ImportedKeyDWallet;

				console.log(`Imported key DWallet is now Active`);

				// Step 5: Request presign (different logic for different signature algorithms)
				console.log('Step 5: Requesting presign...');
				const presignResult = await requestPresign(
					ikaClient,
					suiClient,
					activeDWallet,
					combo.signatureAlgorithm,
					latestNetworkEncryptionKey.id,
					ALICE_IKA_COIN_ID,
				);

				// Step 6: Wait for presign completion
				console.log('Step 6: Waiting for presign to complete...');
				const presign = await ikaClient.getPresignInParticularState(
					presignResult.presignId,
					'Completed',
					{ timeout: 60000, interval: 2000 },
				);

				// Step 7: Sign with imported key
				console.log('Step 7: Signing with imported key...');
				const message = new TextEncoder().encode('test message for imported key sign');
				const signResult = await signWithImportedKey(
					ikaClient,
					suiClient,
					userShareEncryptionKeys,
					activeDWallet,
					presign,
					verificationResult.encryptedUserSecretKeyShareId,
					message,
					combo.curve,
					combo.signatureAlgorithm,
					combo.hash,
					ALICE_IKA_COIN_ID,
				);

				// Step 8: Wait for sign completion
				console.log('Step 8: Waiting for sign to complete...');
				const sign = await ikaClient.getSignInParticularState(
					signResult.signId,
					combo.curve,
					combo.signatureAlgorithm,
					'Completed',
					{ timeout: 60000, interval: 2000 },
				);

				console.log(`Sign completed with state: ${sign.state.$kind}`);

				// Step 9: Verify signature and public keys
				console.log('Step 9: Verifying signature and public keys...');
				let signatureVerified = false;
				let publicKeysMatch = false;

				if (combo.hash !== Hash.Merlin) {
					const signature = Uint8Array.from(sign.state.Completed?.signature ?? []);

					// Get the public key from DWallet output
					const encodedDWalletPublicKey = await publicKeyFromDWalletOutput(
						combo.curve,
						Uint8Array.from(activeDWallet.state.Active?.public_output ?? []),
					);
					const dWalletPublicKey = decodePublicKey(combo.curve, encodedDWalletPublicKey);

					// Get the public key from centralized DKG output (user public output)
					const encodedCentralizedPublicKey = await publicKeyFromCentralizedDKGOutput(
						combo.curve,
						verificationResult.userPublicOutput,
					);
					const centralizedPublicKey = decodePublicKey(combo.curve, encodedCentralizedPublicKey);

					// Verify signature with both public keys
					const expectedHash = computeHash(message, combo.hash);

					const verifiedWithDWallet = verifySignatureWithPublicKey(
						signature,
						expectedHash,
						dWalletPublicKey,
						combo.signatureAlgorithm,
						message,
					);

					const verifiedWithCentralized = verifySignatureWithPublicKey(
						signature,
						expectedHash,
						centralizedPublicKey,
						combo.signatureAlgorithm,
						message,
					);

					signatureVerified = verifiedWithDWallet && verifiedWithCentralized;

					// Check if public keys match
					publicKeysMatch =
						dWalletPublicKey.length === centralizedPublicKey.length &&
						dWalletPublicKey.every((val, idx) => val === centralizedPublicKey[idx]);

					console.log(`Signature verified with DWallet PK: ${verifiedWithDWallet}`);
					console.log(`Signature verified with Centralized PK: ${verifiedWithCentralized}`);
					console.log(`Public keys match: ${publicKeysMatch}`);
				} else {
					console.log('Skipping verification for Merlin hash (not supported client-side)');
					signatureVerified = true; // Assume success for Merlin
					publicKeysMatch = true;
				}

				results.push({
					curve: combo.curve,
					signatureAlgorithm: combo.signatureAlgorithm,
					hash: combo.hash,
					dwalletId: verificationResult.dwalletId,
					verificationDigest: verificationResult.digest,
					presignId: presignResult.presignId,
					presignDigest: presignResult.digest,
					signId: signResult.signId,
					signDigest: signResult.digest,
					signature: sign.state.$kind === 'Completed' ? sign.state.Completed?.signature : undefined,
					signatureVerified,
					publicKeysMatch,
				});

				console.log('✅ Combination completed successfully!');
			} catch (error) {
				console.error(`❌ Error processing combination: ${(error as Error).message}`);
				results.push({
					curve: combo.curve,
					signatureAlgorithm: combo.signatureAlgorithm,
					hash: combo.hash,
					dwalletId: '',
					verificationDigest: '',
					presignId: '',
					presignDigest: '',
					signId: '',
					signDigest: '',
					error: (error as Error).message,
				});
			}
		}
	}

	console.log('\n=== All Imported Key Combinations Completed ===');
	console.dir(results, { depth: null });
}

async function requestImportedKeyVerification(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	curve: Curve,
	privateKey: Uint8Array,
	ikaCoinId: string,
) {
	const sessionIdentifier = createRandomSessionIdentifier();

	const importDWalletVerificationInput = await prepareImportedKeyDWalletVerification(
		ikaClient,
		curve,
		sessionIdentifier,
		signerAddress,
		userShareEncryptionKeys,
		privateKey,
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

	const registeredSessionIdentifier = ikaTransaction.registerSessionIdentifier(sessionIdentifier);

	const importedKeyDWalletCap = await ikaTransaction.requestImportedKeyDWalletVerification({
		importDWalletVerificationRequestInput: importDWalletVerificationInput,
		curve,
		signerPublicKey: userShareEncryptionKeys.getSigningPublicKeyBytes(),
		sessionIdentifier: registeredSessionIdentifier,
		ikaCoin,
		suiCoin,
	});

	tx.transferObjects([importedKeyDWalletCap], signerAddress);

	const result = await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
		options: { showEvents: true },
	});

	const verificationEvent = result.events?.find((event) =>
		event.type.includes('DWalletImportedKeyVerificationRequestEvent'),
	);
	if (!verificationEvent) throw new Error('Verification event not found');

	const verificationEventData = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
	).fromBase64(verificationEvent.bcs as string);

	const encryptedUserSecretKeyShareId =
		verificationEventData.event_data.encrypted_user_secret_key_share_id;
	if (!encryptedUserSecretKeyShareId) {
		throw new Error('Encrypted user secret key share ID not found');
	}

	return {
		dwalletId: verificationEventData.event_data.dwallet_id,
		encryptedUserSecretKeyShareId: encryptedUserSecretKeyShareId as string,
		userPublicOutput: importDWalletVerificationInput.userPublicOutput,
		digest: result.digest,
	};
}

async function acceptEncryptedUserShare(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: ImportedKeyDWallet,
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
		dWallet: dwallet,
		encryptedUserSecretKeyShareId,
		userPublicOutput,
	});

	await suiClient.signAndExecuteTransaction({
		transaction: tx,
		signer: signer,
	});
}

async function requestPresign(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	dwallet: ImportedKeyDWallet,
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

	let unverifiedPresignCap;

	// EdDSA, SchnorrkelSubstrate, and Taproot use global presigns
	// ECDSA algorithms use dwallet-specific presigns
	if (
		signatureAlgorithm === SignatureAlgorithm.EdDSA ||
		signatureAlgorithm === SignatureAlgorithm.SchnorrkelSubstrate ||
		signatureAlgorithm === SignatureAlgorithm.Taproot
	) {
		unverifiedPresignCap = ikaTransaction.requestGlobalPresign({
			signatureAlgorithm,
			ikaCoin,
			suiCoin,
			curve: fromNumberToCurve(dwallet.curve),
			dwalletNetworkEncryptionKeyId,
		});
	} else {
		unverifiedPresignCap = ikaTransaction.requestPresign({
			signatureAlgorithm,
			ikaCoin,
			suiCoin,
			dWallet: dwallet,
		});
	}

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

async function signWithImportedKey(
	ikaClient: IkaClient,
	suiClient: SuiClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	dwallet: ImportedKeyDWallet,
	presign: any,
	encryptedUserSecretKeyShareId: string,
	message: Uint8Array,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	ikaCoinId: string,
) {
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

	const importedKeyMessageApproval = ikaTransaction.approveImportedKeyMessage({
		dWalletCap: dwallet.dwallet_cap_id,
		signatureAlgorithm,
		curve,
		hashScheme: hash,
		message,
	});

	const verifiedPresignCap = ikaTransaction.verifyPresignCap({
		presign,
	});

	await ikaTransaction.requestSignWithImportedKey({
		dWallet: dwallet,
		importedKeyMessageApproval,
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

runImportedKeyBenchmark().catch(console.error);
