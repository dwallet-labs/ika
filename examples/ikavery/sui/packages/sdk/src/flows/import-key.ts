import { solanaSeedToCanonicalScalar } from '@fesal-packages/ikavery-core';
import {
	CoordinatorInnerModule,
	createRandomSessionIdentifier,
	Curve,
	IkaTransaction,
	prepareImportedKeyDWalletVerification,
	SessionsManagerModule,
	type ImportedKeyDWallet,
	type UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import type { Keypair } from '@mysten/sui/cryptography';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';

import type { RecoveryClient } from '../client';
import { executorFromKeypair, type TransactionExecutor } from '../executor';
import { buildNewMembersVec, type NewMemberInput } from '../move/members';

const DEFAULT_IKA_FEE = 1_000_000n;
const DEFAULT_SUI_FEE = 1_000_000n;
const DEFAULT_TIMEOUT_MS = 600_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;

export interface ImportSolanaKeyParams {
	/**
	 * Solana ed25519 private key. Either a 32-byte seed or the 64-byte expanded
	 * form; only the first 32 bytes are used (Ika derives the public key from
	 * the seed itself).
	 */
	solanaSecretKey: Uint8Array;
	/**
	 * Encryption identity for the device performing the import. Built from a
	 * passkey PRF seed via `deriveDeviceIdentity`.
	 */
	userShareEncryptionKeys: UserShareEncryptionKeys;
	/**
	 * Pays gas and signs both PTBs. Decoupled from the recovery-authorization
	 * identity — any Sui address can be the gas payer.
	 *
	 * Pass a `Keypair` for CLI scripts (auto-wrapped) or a {@link TransactionExecutor}
	 * for browser flows that delegate signing to a wallet adapter.
	 */
	gasSigner: Keypair | TransactionExecutor;
	/**
	 * Initial Recovery members. Must include at least one entry; the importer
	 * itself does not need to be in this list (anyone is allowed to call
	 * `propose`/`approve` later, given a valid Credential).
	 */
	initialMembers: NewMemberInput[];
	/** Approval threshold (1 ≤ threshold ≤ initialMembers.length). */
	threshold: number;
	/**
	 * Whether the device's encryption key has already been registered on-chain.
	 * Defaults to `false` — we'll add a `registerEncryptionKey` step to the
	 * verification PTB.
	 */
	encryptionKeyAlreadyRegistered?: boolean;
	/** IKA fee for the verification request. Default 1_000_000 mIKA. */
	verificationIkaFee?: bigint;
	/** SUI fee for the verification request. Default 1_000_000 MIST. */
	verificationSuiFee?: bigint;
	/** Polling timeout for state transitions. Default 10 minutes. */
	timeoutMs?: number;
	/** Polling interval for state transitions. Default 1s. */
	pollIntervalMs?: number;
}

export interface ImportSolanaKeyResult {
	recoveryId: string;
	dwalletId: string;
	encryptedUserShareId: string;
	/** Public output of the imported dWallet, kept for later signing. */
	userPublicOutput: Uint8Array;
	txDigests: { create: string; accept: string };
}

/**
 * One-shot: imports an ed25519 secret key as a zero-trust `imported-key`
 * dWallet, atomically wraps the resulting cap into a freshly-created
 * `Recovery` shared object in the same PTB, then accepts the encrypted user
 * share to drive the dWallet to `Active`.
 *
 * After this returns:
 * - The Recovery object exists with its initial members + threshold + an
 *   IKA/SUI balance ready for presigns.
 * - The dWallet is `Active`; the importer's encryption key holds the only
 *   share. Subsequent devices are added via the t-of-N enrollment flow.
 */
export async function importSolanaKey(
	client: RecoveryClient,
	params: ImportSolanaKeyParams,
): Promise<ImportSolanaKeyResult> {
	if (params.solanaSecretKey.length !== 32 && params.solanaSecretKey.length !== 64) {
		throw new Error(
			`importSolanaKey: solanaSecretKey must be 32 or 64 bytes, got ${params.solanaSecretKey.length}`,
		);
	}
	// Solana exposes a 32-byte SEED (or 64-byte seed||pubkey). Ika expects the
	// canonical Ed25519 SCALAR (< L). Derive it via `clamp(SHA512(seed)) mod L`.
	const seed = params.solanaSecretKey.subarray(0, 32);
	const canonicalScalar = solanaSeedToCanonicalScalar(seed);
	if (params.initialMembers.length === 0) {
		throw new Error('importSolanaKey: initialMembers must be non-empty');
	}
	if (params.threshold < 1 || params.threshold > params.initialMembers.length) {
		throw new Error(
			`importSolanaKey: threshold ${params.threshold} out of range [1, ${params.initialMembers.length}]`,
		);
	}

	const ikaClient = client.ikaClient;
	const suiClient = client.suiClient;
	const packageId = client.ref.packageId;
	// Auto-wrap a bare Keypair so CLI scripts keep working unchanged.
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, suiClient);
	const gasSignerAddress = executor.address;
	const networkKey = await ikaClient.getLatestNetworkEncryptionKey();

	const sessionIdBytes = createRandomSessionIdentifier();
	const importInput = await prepareImportedKeyDWalletVerification(
		ikaClient,
		Curve.ED25519,
		sessionIdBytes,
		gasSignerAddress,
		params.userShareEncryptionKeys,
		canonicalScalar,
	);

	// ── PTB 1: register encryption key (optional) + verify import + create Recovery ──
	const createTx = new Transaction();
	const ikaTx = new IkaTransaction({
		ikaClient,
		transaction: createTx,
		userShareEncryptionKeys: params.userShareEncryptionKeys,
	});

	// Skip registration if either explicitly told or if we can detect that the
	// encryption key is already on-chain (re-running on the same device).
	let alreadyRegistered = params.encryptionKeyAlreadyRegistered === true;
	if (!alreadyRegistered) {
		try {
			await ikaClient.getActiveEncryptionKey(params.userShareEncryptionKeys.getSuiAddress());
			alreadyRegistered = true;
		} catch {
			/* not registered yet */
		}
	}
	if (!alreadyRegistered) {
		await ikaTx.registerEncryptionKey({ curve: Curve.ED25519 });
	}

	const sessionId = ikaTx.registerSessionIdentifier(sessionIdBytes);

	const verifyIkaFee = params.verificationIkaFee ?? DEFAULT_IKA_FEE;
	const verifySuiFee = params.verificationSuiFee ?? DEFAULT_SUI_FEE;
	const verifyIkaCoin = coinWithBalance({
		balance: verifyIkaFee,
		type: client.ikaCoinType,
	});
	const verifySuiCoin = coinWithBalance({ balance: verifySuiFee });

	const importedKeyCap = await ikaTx.requestImportedKeyDWalletVerification({
		importDWalletVerificationRequestInput: importInput,
		curve: Curve.ED25519,
		signerPublicKey: params.userShareEncryptionKeys.getSigningPublicKeyBytes(),
		sessionIdentifier: sessionId,
		ikaCoin: verifyIkaCoin,
		suiCoin: verifySuiCoin,
	});

	const initialMembersArg = buildNewMembersVec(createTx, packageId, params.initialMembers);

	client.move.create({
		importedKeyCap,
		initialMembers: initialMembersArg,
		threshold: BigInt(params.threshold),
		dwalletNetworkEncryptionKeyId: networkKey.id,
		registry: createTx.object(client.ref.registryId),
	})(createTx);
	createTx.transferObjects([verifyIkaCoin, verifySuiCoin], gasSignerAddress);

	const createResult = await executor.signAndExecute(createTx);
	if (createResult.$kind !== 'Transaction') {
		throw new Error(
			`importSolanaKey: create+import transaction failed: ${JSON.stringify(createResult.FailedTransaction.status)}`,
		);
	}
	const createTxData = createResult.Transaction;
	const createDigest = createTxData.digest;

	const verificationEvent = createTxData.events.find((e) =>
		e.eventType.includes('DWalletImportedKeyVerificationRequestEvent'),
	);
	if (!verificationEvent?.bcs) {
		throw new Error(
			'importSolanaKey: DWalletImportedKeyVerificationRequestEvent missing from create-tx events',
		);
	}
	const parsed = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
	).parse(new Uint8Array(verificationEvent.bcs));
	const dwalletId = parsed.event_data.dwallet_id;
	const encryptedUserShareId = parsed.event_data.encrypted_user_secret_key_share_id;

	const recoveryObjectType = `${packageId}::recovery::Recovery`;
	const recoveryCreated = createTxData.effects.changedObjects.find(
		(c) =>
			c.idOperation === 'Created' && createTxData.objectTypes[c.objectId] === recoveryObjectType,
	);
	if (!recoveryCreated) {
		throw new Error(
			`importSolanaKey: Recovery object (${recoveryObjectType}) not found in created objects`,
		);
	}
	const recoveryId = recoveryCreated.objectId;

	// ── Wait for dWallet to reach AwaitingKeyHolderSignature ──
	const awaitingDWallet = (await ikaClient.getDWalletInParticularState(
		dwalletId,
		'AwaitingKeyHolderSignature',
		{
			timeout: params.timeoutMs ?? DEFAULT_TIMEOUT_MS,
			interval: params.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
		},
	)) as ImportedKeyDWallet;

	// ── PTB 2: accept encrypted user share to move dWallet to Active ──
	const acceptTx = new Transaction();
	const acceptIkaTx = new IkaTransaction({
		ikaClient,
		transaction: acceptTx,
		userShareEncryptionKeys: params.userShareEncryptionKeys,
	});
	await acceptIkaTx.acceptEncryptedUserShare({
		dWallet: awaitingDWallet,
		userPublicOutput: importInput.userPublicOutput,
		encryptedUserSecretKeyShareId: encryptedUserShareId,
	});
	const acceptResult = await executor.signAndExecute(acceptTx);
	if (acceptResult.$kind !== 'Transaction') {
		throw new Error(
			`importSolanaKey: accept-share transaction failed: ${JSON.stringify(acceptResult.FailedTransaction.status)}`,
		);
	}
	const acceptDigest = acceptResult.Transaction.digest;

	// Drive to Active before returning so the caller can immediately use the dWallet.
	await ikaClient.getDWalletInParticularState(dwalletId, 'Active', {
		timeout: params.timeoutMs ?? DEFAULT_TIMEOUT_MS,
		interval: params.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
	});

	return {
		recoveryId,
		dwalletId,
		encryptedUserShareId,
		userPublicOutput: importInput.userPublicOutput,
		txDigests: { create: createDigest, accept: acceptDigest },
	};
}
