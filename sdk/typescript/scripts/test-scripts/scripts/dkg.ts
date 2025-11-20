import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { SerialTransactionExecutor, Transaction } from '@mysten/sui/transactions';

import { CoordinatorInnerModule, SessionsManagerModule } from '../../../src';
import { createRandomSessionIdentifier, prepareDKGAsync } from '../../../src/client/cryptography';
import {
	fromNumberToCurve,
	fromNumberToHash,
	fromNumberToSignatureAlgorithm,
	ValidHashForSignature,
	ValidSignatureAlgorithmForCurve,
} from '../../../src/client/hash-signature-validation';
import { IkaClient } from '../../../src/client/ika-client';
import { IkaTransaction } from '../../../src/client/ika-transaction';
import { getNetworkConfig } from '../../../src/client/network-configs';
import { Curve, Hash, SignatureAlgorithm } from '../../../src/client/types';
import { UserShareEncryptionKeys } from '../../../src/client/user-share-encryption-keys';
import { dwalletId } from '../../../src/generated/ika_dwallet_2pc_mpc/coordinator_inner';
import { ALICE_IKA_COIN_ID, signer, signerAddress } from './const';

// Presign IDs for sign-during-DKG operations
const PRESIGNS = {
	SECP256K1_ECDSA_KECCAK256: '0x87c9fb403c4503990400e66120350fdb95cef400d5882f48308457a4b45d56b9',
	SECP256K1_ECDSA_SHA256: '0x8afe04421904f9b3efb11e164646517446f399bc57d153f4e26dd07f65cb5810',
	SECP256K1_ECDSA_DOUBLESHA256:
		'0xa58798e595e9e271385358b6737f35078624307f0509eb42b6ec06701ff922a6',
	SECP256K1_TAPROOT: '0x77b97257c773b236add1d3489bfe4f6493544bcd47729c8643801be0a424c671',
	SECP256R1_ECDSA: '0x6bad243cc2c3a29f3e4ca35c67c9f2b141d0e7992896837e8354635657068ec2',
	ED25519_EDDSA: '0xfd90413cd87d7d426ee7e05964fee14ef415fe8f426530e0bab79374a39ef4f2',
	RISTRETTO_SCHNORRKEL: '0x051d4aaac8ff235b0108c45811184fe95b649491368697bbc3609ce437c038be',
};

type CurveSignatureHashCombination =
	| {
			curve: typeof Curve.SECP256K1;
			signatureAlgorithm: typeof SignatureAlgorithm.ECDSASecp256k1;
			hash: typeof Hash.KECCAK256 | typeof Hash.SHA256 | typeof Hash.DoubleSHA256;
			signDuringDKG: boolean;
	  }
	| {
			curve: typeof Curve.SECP256K1;
			signatureAlgorithm: typeof SignatureAlgorithm.Taproot;
			hash: typeof Hash.SHA256;
			signDuringDKG: boolean;
	  }
	| {
			curve: typeof Curve.SECP256R1;
			signatureAlgorithm: typeof SignatureAlgorithm.ECDSASecp256r1;
			hash: typeof Hash.SHA256;
			signDuringDKG: boolean;
	  }
	| {
			curve: typeof Curve.ED25519;
			signatureAlgorithm: typeof SignatureAlgorithm.EdDSA;
			hash: typeof Hash.SHA512;
			signDuringDKG: boolean;
	  }
	| {
			curve: typeof Curve.RISTRETTO;
			signatureAlgorithm: typeof SignatureAlgorithm.SchnorrkelSubstrate;
			hash: typeof Hash.Merlin;
			signDuringDKG: boolean;
	  };

// Base combinations without signDuringDKG flag
const baseCombinations = [
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
] as const;

// Expand combinations to include both with and without signDuringDKG
const combinations: CurveSignatureHashCombination[] = baseCombinations.flatMap((base) => [
	{ ...base, signDuringDKG: true },
	{ ...base, signDuringDKG: false },
]);

export async function runDKG() {
	const suiClient = new SuiClient({ url: 'https://sui-testnet-rpc.publicnode.com' });

	const ikaClient = new IkaClient({
		suiClient,
		config: getNetworkConfig('testnet'),
	});

	await ikaClient.initialize();

	// Create SerialTransactionExecutor for efficient sequential execution
	const executor = new SerialTransactionExecutor({
		client: suiClient,
		signer: signer,
	});

	const latestNetworkEncryptionKey = await ikaClient.getLatestNetworkEncryptionKey();

	// Group combinations by curve to avoid redundant encryption key registration
	const curveMap = new Map<Curve, CurveSignatureHashCombination[]>();
	for (const combo of combinations) {
		if (!curveMap.has(combo.curve)) {
			curveMap.set(combo.curve, []);
		}
		curveMap.get(combo.curve)!.push(combo);
	}

	const allDkgType: {
		dwalletId: string;
		curve: Curve;
		signatureAlgorithm?: SignatureAlgorithm;
		hash?: Hash;
		signId?: string;
		digest: string;
	}[] = [];

	for (const [curve, combos] of curveMap) {
		const userShareEncryptionKeys = await UserShareEncryptionKeys.fromRootSeedKey(
			new TextEncoder().encode('test seed' + curve),
			curve,
		);

		// Create a transaction for encryption key registration
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
		const encryptionResult = await executor.executeTransaction(encryptionKeyTx).catch((error) => {
			console.log('The encryption key was already registered');
			return {
				digest: 'already registered',
			};
		});
		console.log(`Encryption key registered. Digest: ${encryptionResult.digest}`);

		// Create and execute a separate transaction for each DKG combination
		for (const combo of combos) {
			const tx = new Transaction();
			tx.setSender(signerAddress);
			tx.setGasBudget(1_000_000_000);
			const ikaCoin = tx.object(ALICE_IKA_COIN_ID);
			const suiCoin = tx.gas;

			const ikaTransaction = new IkaTransaction({
				ikaClient,
				transaction: tx,
				userShareEncryptionKeys,
			});

			await requestDKGForCombination(
				ikaClient,
				tx,
				ikaTransaction,
				userShareEncryptionKeys,
				combo.curve,
				combo.signatureAlgorithm,
				combo.hash,
				combo.signDuringDKG,
				latestNetworkEncryptionKey.id,
				ikaCoin,
				suiCoin,
			);

			console.log(
				`Executing DKG for ${combo.curve} - ${combo.signatureAlgorithm} - ${combo.hash} (signDuringDKG: ${combo.signDuringDKG})...`,
			);
			const result = await executor.executeTransaction(tx, {
				showEvents: true,
			});

			console.log(`DKG executed. Digest: ${result.digest}`);

			const dkgEvents = result.data.events?.filter((event) =>
				event.type.includes('DWalletDKGRequestEvent'),
			);

			for (const dkgEvent of dkgEvents ?? []) {
				const dkgEventData = SessionsManagerModule.DWalletSessionEvent(
					CoordinatorInnerModule.DWalletDKGRequestEvent,
				).fromBase64(dkgEvent.bcs as string);

				const curve = fromNumberToCurve(dkgEventData.event_data.curve);
				const signDuringDkgRequest = dkgEventData.event_data.sign_during_dkg_request;

				allDkgType.push({
					dwalletId: dkgEventData.event_data.dwallet_id,
					curve,
					signatureAlgorithm: signDuringDkgRequest
						? fromNumberToSignatureAlgorithm(
								curve,
								signDuringDkgRequest.signature_algorithm as number,
							)
						: undefined,
					hash: signDuringDkgRequest
						? fromNumberToHash(
								curve,
								fromNumberToSignatureAlgorithm(
									curve,
									signDuringDkgRequest.signature_algorithm as number,
								),
								signDuringDkgRequest.hash_scheme as number,
							)
						: undefined,
					signId: signDuringDkgRequest?.sign_id,
					digest: result.digest,
				});
			}
		}
	}

	console.log('\n=== All DKG Operations Completed ===');
	console.dir(allDkgType, { depth: null });

	// Check sign status and dwallet states
	console.log('\n=== Checking Sign Status and DWallet States ===');

	const results: Array<{
		dwalletId: string;
		curve: Curve;
		digest: string;
		signStatus?: string;
		signId?: string;
		signature?: number[];
		signError?: string;
		dwalletState?: string;
		dwalletKind?: string;
		awaitingKeyHolderSignature?: boolean;
		dwalletError?: string;
	}> = [];

	for (const dkg of allDkgType) {
		const result: {
			dwalletId: string;
			curve: Curve;
			digest: string;
			signStatus?: string;
			signId?: string;
			signature?: number[];
			signError?: string;
			dwalletState?: string;
			dwalletKind?: string;
			awaitingKeyHolderSignature?: boolean;
			dwalletError?: string;
		} = {
			dwalletId: dkg.dwalletId,
			curve: dkg.curve,
			digest: dkg.digest,
		};

		// Check sign status if this was a sign-during-DKG operation
		if (dkg.signId && dkg.signatureAlgorithm && dkg.hash) {
			console.log(`Waiting for sign ${dkg.signId} to complete...`);
			try {
				const sign = await ikaClient.getSignInParticularState(
					dkg.signId,
					dkg.curve,
					dkg.signatureAlgorithm,
					'Completed',
					{
						timeout: 60000, // 60 seconds
						interval: 2000, // 2 seconds
					},
				);
				result.signStatus = sign.state.$kind;
				result.signId = dkg.signId;

				if (sign.state.$kind === 'Completed') {
					result.signature = sign.state.Completed.signature;
				}
				console.log(`Sign ${dkg.signId} completed successfully`);
			} catch (error) {
				result.signError = (error as Error).message;
				console.log(`Sign ${dkg.signId} failed: ${result.signError}`);
			}
		}

		// Check dwallet state - wait for Active state
		console.log(`Waiting for dwallet ${dkg.dwalletId} to become Active...`);
		try {
			const dwallet = await ikaClient.getDWalletInParticularState(
				dkg.dwalletId,
				'AwaitingKeyHolderSignature',
				{
					timeout: 60000, // 60 seconds
					interval: 2000, // 2 seconds
				},
			);
			result.dwalletState = dwallet.state.$kind;
			result.dwalletKind = dwallet.kind;
			console.log(`DWallet ${dkg.dwalletId} is now ${dwallet.state.$kind}`);
		} catch (error) {
			// If it doesn't reach Active, check if it's in AwaitingKeyHolderSignature
			try {
				const dwallet = await ikaClient.getDWallet(dkg.dwalletId);
				result.dwalletState = dwallet.state.$kind;
				result.dwalletKind = dwallet.kind;

				if (dwallet.state.$kind === 'AwaitingKeyHolderSignature') {
					result.awaitingKeyHolderSignature = true;
					console.log(`DWallet ${dkg.dwalletId} is awaiting key holder signature`);
				}
			} catch (innerError) {
				result.dwalletError = (innerError as Error).message;
				console.log(`DWallet ${dkg.dwalletId} error: ${result.dwalletError}`);
			}
		}

		results.push(result);
	}

	console.log('\n=== Results ===');
	console.dir(results, { depth: null });
}

async function prepareDKG(
	ikaClient: IkaClient,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	signerAddress: string,
	curve: Curve,
) {
	const randomSessionIdentifier = createRandomSessionIdentifier();

	const dkgRequestInput = await prepareDKGAsync(
		ikaClient,
		curve,
		userShareEncryptionKeys,
		randomSessionIdentifier,
		signerAddress,
	);

	return {
		dkgRequestInput,
		sessionIdentifier: randomSessionIdentifier,
	};
}

function getPresignId(curve: Curve, signatureAlgorithm: SignatureAlgorithm, hash: Hash): string {
	if (curve === Curve.SECP256K1 && signatureAlgorithm === SignatureAlgorithm.ECDSASecp256k1) {
		if (hash === Hash.KECCAK256) return PRESIGNS.SECP256K1_ECDSA_KECCAK256;
		if (hash === Hash.SHA256) return PRESIGNS.SECP256K1_ECDSA_SHA256;
		if (hash === Hash.DoubleSHA256) return PRESIGNS.SECP256K1_ECDSA_DOUBLESHA256;
	}
	if (curve === Curve.SECP256K1 && signatureAlgorithm === SignatureAlgorithm.Taproot) {
		return PRESIGNS.SECP256K1_TAPROOT;
	}
	if (curve === Curve.SECP256R1 && signatureAlgorithm === SignatureAlgorithm.ECDSASecp256r1) {
		return PRESIGNS.SECP256R1_ECDSA;
	}
	if (curve === Curve.ED25519 && signatureAlgorithm === SignatureAlgorithm.EdDSA) {
		return PRESIGNS.ED25519_EDDSA;
	}
	if (curve === Curve.RISTRETTO && signatureAlgorithm === SignatureAlgorithm.SchnorrkelSubstrate) {
		return PRESIGNS.RISTRETTO_SCHNORRKEL;
	}
	throw new Error(`No presign found for combination: ${curve}, ${signatureAlgorithm}, ${hash}`);
}

async function requestDKGForCombination(
	ikaClient: IkaClient,
	tx: Transaction,
	ikaTransaction: IkaTransaction,
	userShareEncryptionKeys: UserShareEncryptionKeys,
	curve: Curve,
	signatureAlgorithm: SignatureAlgorithm,
	hash: Hash,
	signDuringDKG: boolean,
	dwalletNetworkEncryptionKeyId: string,
	ikaCoin: any,
	suiCoin: any,
) {
	const { dkgRequestInput, sessionIdentifier } = await prepareDKG(
		ikaClient,
		userShareEncryptionKeys,
		signerAddress,
		curve,
	);

	// Common parameters for DKG request
	const commonParams = {
		curve,
		dkgRequestInput,
		sessionIdentifier: ikaTransaction.registerSessionIdentifier(sessionIdentifier),
		dwalletNetworkEncryptionKeyId,
		ikaCoin,
		suiCoin,
	};

	// If not signing during DKG, just call without signDuringDKGRequest
	if (!signDuringDKG) {
		const [dWalletCap, _] = await ikaTransaction.requestDWalletDKG(commonParams);

		tx.transferObjects([dWalletCap], signerAddress);

		return;
	}

	// Get presign for signing during DKG using hardcoded presign ID
	const presignId = getPresignId(curve, signatureAlgorithm, hash);
	const presign = await ikaClient.getPresignInParticularState(presignId, 'Completed');

	if (!presign) {
		throw new Error(`Presign not found for combination: ${curve}, ${signatureAlgorithm}, ${hash}`);
	}

	let dWalletCap: any;

	// Use explicit conditional logic to properly narrow types for signing during DKG
	if (signatureAlgorithm === SignatureAlgorithm.ECDSASecp256k1) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKG({
			...commonParams,
			signDuringDKGRequest: {
				message: new TextEncoder().encode('test message'),
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.ECDSASecp256k1>,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
			},
		});
	} else if (signatureAlgorithm === SignatureAlgorithm.Taproot) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKG({
			...commonParams,
			signDuringDKGRequest: {
				message: new TextEncoder().encode('test message'),
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.Taproot>,
				signatureAlgorithm: SignatureAlgorithm.Taproot,
			},
		});
	} else if (signatureAlgorithm === SignatureAlgorithm.ECDSASecp256r1) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKG({
			...commonParams,
			signDuringDKGRequest: {
				message: new TextEncoder().encode('test message'),
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.ECDSASecp256r1>,
				signatureAlgorithm: SignatureAlgorithm.ECDSASecp256r1,
			},
		});
	} else if (signatureAlgorithm === SignatureAlgorithm.EdDSA) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKG({
			...commonParams,
			signDuringDKGRequest: {
				message: new TextEncoder().encode('test message'),
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.EdDSA>,
				signatureAlgorithm: SignatureAlgorithm.EdDSA,
			},
		});
	} else if (signatureAlgorithm === SignatureAlgorithm.SchnorrkelSubstrate) {
		[dWalletCap] = await ikaTransaction.requestDWalletDKG({
			...commonParams,
			signDuringDKGRequest: {
				message: new TextEncoder().encode('test message'),
				presign,
				verifiedPresignCap: ikaTransaction.verifyPresignCap({ presign }),
				hashScheme: hash as ValidHashForSignature<typeof SignatureAlgorithm.SchnorrkelSubstrate>,
				signatureAlgorithm: SignatureAlgorithm.SchnorrkelSubstrate,
			},
		});
	}

	tx.transferObjects([dWalletCap], signerAddress);
}

runDKG().catch(console.error);
