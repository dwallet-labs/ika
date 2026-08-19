import {
	CoordinatorInnerModule,
	Curve,
	IkaTransaction,
	SessionsManagerModule,
	type EncryptedUserSecretKeyShare,
	type EncryptionKey,
	type ImportedKeyDWallet,
	type UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import type { Keypair } from '@mysten/sui/cryptography';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';

import type { RecoveryClient } from '../client';
import { executorFromKeypair, type TransactionExecutor } from '../executor';

// Sized for the testnet re-encryption protocol fee. The earlier 1M mIKA
// default tripped EInsufficientIKAPayment in sessions_manager — the
// re-encryption initiation costs a couple hundred million mIKA on testnet,
// matching the import-verification + presign call pricing.
const DEFAULT_IKA_FEE = 500_000_000n;
const DEFAULT_SUI_FEE = 50_000_000n;
const DEFAULT_TIMEOUT_MS = 600_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;

export type ProvisionPhase = 'registering' | 'reEncrypting' | 'waitingVerification' | 'accepting';

export interface ProvisionRosterMemberParams {
	/**
	 * Importer's encryption identity. Holds the only decryptable copy of the
	 * user share before this call; we use it to decrypt + re-encrypt to the
	 * member's encryption key.
	 */
	importerEncryptionKeys: UserShareEncryptionKeys;
	/** The importer's `EncryptedUserSecretKeyShare` (source for re-encryption). */
	importerEncryptedUserShare: EncryptedUserSecretKeyShare;
	/** Imported-key dWallet whose share we're sharing with the member. */
	dwalletId: string;
	/**
	 * The member's encryption identity. The importer holds this for the
	 * duration of setup (derived from the member's PRF or wallet-signature
	 * seed in the same browser session).
	 */
	memberEncryptionKeys: UserShareEncryptionKeys;
	/** Pays gas for all 3 PTBs. */
	gasSigner: Keypair | TransactionExecutor;
	ikaFee?: bigint;
	suiFee?: bigint;
	timeoutMs?: number;
	pollIntervalMs?: number;
	onProgress?: (phase: ProvisionPhase) => void;
}

export interface ProvisionRosterMemberResult {
	destEncryptedUserShareId: string;
	digests: {
		register: string | null;
		reEncrypt: string;
		accept: string;
	};
}

/**
 * Provision a non-importer roster member with a decryptable share for an
 * imported-key dWallet. Three PTBs:
 *
 *   1. `registerEncryptionKey` for the member (idempotent — skipped if the
 *      member's encryption key is already on Ika).
 *   2. `requestReEncryptUserShareFor` — importer decrypts their own share and
 *      re-encrypts to the member's class-groups public key.
 *   3. `acceptEncryptedUserShare` — signed by the member's keys to mark the
 *      destination share as owned. The importer holds those keys here, so
 *      the gas signer signs the PTB and the member's keypair signs the
 *      user-output confirmation inside it.
 *
 * Designed to be called once per non-importer member at setup time; the
 * post-import enrollment ceremony covers the same ground for members added
 * after the initial setup.
 */
export async function provisionRosterMember(
	client: RecoveryClient,
	params: ProvisionRosterMemberParams,
): Promise<ProvisionRosterMemberResult> {
	const ikaClient = client.ikaClient;
	const suiClient = client.suiClient;
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, suiClient);
	const gasAddress = executor.address;
	const ikaFee = params.ikaFee ?? DEFAULT_IKA_FEE;
	const suiFee = params.suiFee ?? DEFAULT_SUI_FEE;
	const timeoutMs = params.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const pollIntervalMs = params.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
	const memberAddress = params.memberEncryptionKeys.getSuiAddress();

	// ── Step 1: register the member's encryption key (idempotent) ──
	params.onProgress?.('registering');
	let registerDigest: string | null = null;
	let memberAlreadyRegistered = false;
	try {
		await ikaClient.getActiveEncryptionKey(memberAddress);
		memberAlreadyRegistered = true;
	} catch {
		/* not registered yet */
	}
	if (!memberAlreadyRegistered) {
		const tx = new Transaction();
		const ikaTx = new IkaTransaction({
			ikaClient,
			transaction: tx,
			userShareEncryptionKeys: params.memberEncryptionKeys,
		});
		await ikaTx.registerEncryptionKey({ curve: Curve.ED25519 });
		const result = await executor.signAndExecute(tx);
		if (result.$kind !== 'Transaction') {
			throw new Error(
				`provisionRosterMember.register: failed: ${JSON.stringify(result.FailedTransaction.status)}`,
			);
		}
		registerDigest = result.Transaction.digest;
	}

	// ── Step 2: re-encrypt importer's share to the member's encryption key ──
	params.onProgress?.('reEncrypting');
	const dWallet = (await ikaClient.getDWalletInParticularState(params.dwalletId, 'Active', {
		timeout: timeoutMs,
		interval: pollIntervalMs,
	})) as ImportedKeyDWallet;

	const reTx = new Transaction();
	const reIkaTx = new IkaTransaction({
		ikaClient,
		transaction: reTx,
		userShareEncryptionKeys: params.importerEncryptionKeys,
	});
	const reIkaCoin = coinWithBalance({
		balance: ikaFee,
		type: client.ikaCoinType,
	});
	const reSuiCoin = coinWithBalance({ balance: suiFee });
	await reIkaTx.requestReEncryptUserShareFor({
		dWallet,
		destinationEncryptionKeyAddress: memberAddress,
		sourceEncryptedUserSecretKeyShare: params.importerEncryptedUserShare,
		ikaCoin: reIkaCoin,
		suiCoin: reSuiCoin,
	});
	reTx.transferObjects([reIkaCoin, reSuiCoin], gasAddress);
	const reResult = await executor.signAndExecute(reTx);
	if (reResult.$kind !== 'Transaction') {
		throw new Error(
			`provisionRosterMember.reEncrypt: failed: ${JSON.stringify(reResult.FailedTransaction.status)}`,
		);
	}
	const reDigest = reResult.Transaction.digest;
	const reEvent = reResult.Transaction.events.find((e) =>
		e.eventType.includes('EncryptedShareVerificationRequestEvent'),
	);
	if (!reEvent?.bcs) {
		throw new Error(
			'provisionRosterMember.reEncrypt: EncryptedShareVerificationRequestEvent missing',
		);
	}
	const parsed = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.EncryptedShareVerificationRequestEvent,
	).parse(new Uint8Array(reEvent.bcs));
	const destEncryptedUserShareId = parsed.event_data.encrypted_user_secret_key_share_id;

	// ── Step 3: wait for verification, then accept on the member's behalf ──
	params.onProgress?.('waitingVerification');
	const destShare = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
		destEncryptedUserShareId,
		'NetworkVerificationCompleted',
		{ timeout: timeoutMs, interval: pollIntervalMs },
	);

	// Look up the importer's encryption key object by id (used inside the
	// member's accept-share to verify the source-of-truth on-chain).
	const sourceEncryptionKey = await fetchEncryptionKey(
		client,
		params.importerEncryptedUserShare.encryption_key_id,
	);

	params.onProgress?.('accepting');
	const acceptTx = new Transaction();
	const acceptIkaTx = new IkaTransaction({
		ikaClient,
		transaction: acceptTx,
		userShareEncryptionKeys: params.memberEncryptionKeys,
	});
	await acceptIkaTx.acceptEncryptedUserShare({
		dWallet,
		sourceEncryptionKey,
		sourceEncryptedUserSecretKeyShare: params.importerEncryptedUserShare,
		destinationEncryptedUserSecretKeyShare: destShare,
	});
	const acceptResult = await executor.signAndExecute(acceptTx);
	if (acceptResult.$kind !== 'Transaction') {
		throw new Error(
			`provisionRosterMember.accept: failed: ${JSON.stringify(acceptResult.FailedTransaction.status)}`,
		);
	}
	const acceptDigest = acceptResult.Transaction.digest;

	return {
		destEncryptedUserShareId,
		digests: {
			register: registerDigest,
			reEncrypt: reDigest,
			accept: acceptDigest,
		},
	};
}

async function fetchEncryptionKey(
	client: RecoveryClient,
	encryptionKeyId: string,
): Promise<EncryptionKey> {
	const { object } = await client.suiClient.core.getObject({
		objectId: encryptionKeyId,
		include: { content: true },
	});
	if (!object.content) {
		throw new Error(
			`provisionRosterMember.fetchEncryptionKey: object ${encryptionKeyId} returned no content`,
		);
	}
	return CoordinatorInnerModule.EncryptionKey.parse(object.content) as EncryptionKey;
}
