import { solanaSeedToCanonicalScalar } from '@fesal-packages/ikavery-core';
import {
	CoordinatorInnerModule,
	coordinatorTransactions,
	createRandomSessionIdentifier,
	Curve,
	encryptSecretShare,
	IkaTransaction,
	prepareImportedKeyDWalletVerification,
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
import { buildNewMembersVec, type NewMemberInput } from '../move/members';

const DEFAULT_VERIFY_IKA_FEE = 500_000_000n;
const DEFAULT_VERIFY_SUI_FEE = 50_000_000n;
const DEFAULT_REENCRYPT_IKA_FEE = 500_000_000n;
const DEFAULT_REENCRYPT_SUI_FEE = 50_000_000n;
const DEFAULT_TIMEOUT_MS = 600_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;

export type ProvisionInitialMembersPhase =
	'preparing' | 'creating' | 'reEncrypting' | 'waitingVerification' | 'accepting';

/**
 * One slot in the non-importer side of the initial roster, parallel to
 * `initialMembers[1..]`. Key-holders go through register-encrypt-accept;
 * approver-only members (sender_address) are added to the on-chain roster
 * but skipped in per-member share-distribution work — they never hold a
 * decryptable share, so they can vote but cannot execute.
 */
export type NonImporterMember =
	{ kind: 'key-holder'; keys: UserShareEncryptionKeys } | { kind: 'approver-only' };

export interface ProvisionInitialMembersParams {
	/** 32 or 64 byte Solana ed25519 seed (only first 32 bytes used). */
	solanaSecretKey: Uint8Array;
	/** Importer's encryption identity. */
	importerEncryptionKeys: UserShareEncryptionKeys;
	/**
	 * Per-non-importer-member info, ordered to match the non-importer slice of
	 * `initialMembers` (index 0 here corresponds to `initialMembers[1]`).
	 * Approver-only entries are skipped in the encryption-key register, the
	 * re-encrypt loop, and the accept loop.
	 */
	nonImporterMembers: NonImporterMember[];
	/** Full roster (importer first). */
	initialMembers: NewMemberInput[];
	threshold: number;
	/** Pays gas for all 3 PTBs. */
	gasSigner: Keypair | TransactionExecutor;

	verificationIkaFee?: bigint;
	verificationSuiFee?: bigint;
	reEncryptIkaFee?: bigint;
	reEncryptSuiFee?: bigint;
	timeoutMs?: number;
	pollIntervalMs?: number;
	onProgress?: (phase: ProvisionInitialMembersPhase) => void;
}

export interface ProvisionInitialMembersResult {
	recoveryId: string;
	dwalletId: string;
	importerEncryptedUserShareId: string;
	/**
	 * Per-non-importer-member, parallel to `nonImporterMembers`.
	 * `null` for approver-only entries (no share was created for them).
	 */
	nonImporterEncryptedUserShareIds: Array<string | null>;
	txDigests: {
		create: string;
		/** `null` if every non-importer member is approver-only. */
		reEncrypt: string | null;
		/** `null` if every non-importer member is approver-only. */
		accept: string | null;
	};
}

/**
 * 3-PTB setup that provisions every initial member with a decryptable share
 * in one sitting. Each PTB is signed by the gas payer; member keypairs are
 * derived locally (passkey PRF or wallet personal-message hash) and used to
 * sign in-PTB user-output confirmations — there are no per-member wallet
 * popups during setup.
 *
 * PTB1  register every member's encryption key
 *       + import-key DKG verification
 *       + create Recovery
 *
 * PTB2  importer accept-share
 *       + re-encrypt importer's share to each non-importer member
 *
 * PTB3  accept-share for each non-importer member, each signed with that
 *       member's keypair held locally for the duration of the session.
 *
 * Total: 3 PTBs regardless of N members, so the wallet popup count for the
 * gas payer doesn't grow with the roster size.
 */
export async function provisionInitialMembers(
	client: RecoveryClient,
	params: ProvisionInitialMembersParams,
): Promise<ProvisionInitialMembersResult> {
	if (params.solanaSecretKey.length !== 32 && params.solanaSecretKey.length !== 64) {
		throw new Error(
			`provisionInitialMembers: solanaSecretKey must be 32 or 64 bytes, got ${params.solanaSecretKey.length}`,
		);
	}
	if (params.initialMembers.length === 0) {
		throw new Error('provisionInitialMembers: initialMembers must be non-empty');
	}
	if (params.threshold < 1 || params.threshold > params.initialMembers.length) {
		throw new Error(
			`provisionInitialMembers: threshold ${params.threshold} out of range [1, ${params.initialMembers.length}]`,
		);
	}
	if (params.nonImporterMembers.length !== params.initialMembers.length - 1) {
		throw new Error(
			`provisionInitialMembers: nonImporterMembers length ${params.nonImporterMembers.length} must equal initialMembers.length-1 (${params.initialMembers.length - 1})`,
		);
	}
	// Importer must be a key-holder — they're the source of the share that gets
	// re-encrypted to the others. Approver-only at index 0 is structurally
	// impossible (no share to encrypt at all).
	if (params.initialMembers[0]!.scheme === 'sender_address') {
		throw new Error(
			'provisionInitialMembers: importer (initialMembers[0]) cannot be ' +
				"sender_address — the importer's encryption identity is what holds " +
				'the imported user share.',
		);
	}
	// Each non-importer member's `kind` must match the scheme: a key-holder
	// entry pairs with a raw-key scheme; approver-only pairs with sender_address.
	// This catches the most common misconfiguration: caller forgot to mark a
	// sender_address member as approver-only and passed encryption keys for it.
	for (let i = 1; i < params.initialMembers.length; i++) {
		const memberScheme = params.initialMembers[i]!.scheme;
		const slot = params.nonImporterMembers[i - 1]!;
		const isAddress = memberScheme === 'sender_address';
		if (isAddress && slot.kind !== 'approver-only') {
			throw new Error(
				`provisionInitialMembers: initialMembers[${i}] is sender_address ` +
					`but nonImporterMembers[${i - 1}] is ${slot.kind}; pass { kind: "approver-only" } instead.`,
			);
		}
		if (!isAddress && slot.kind !== 'key-holder') {
			throw new Error(
				`provisionInitialMembers: initialMembers[${i}] is ${memberScheme} ` +
					`but nonImporterMembers[${i - 1}] is ${slot.kind}; pass { kind: "key-holder", keys } instead.`,
			);
		}
	}

	const ikaClient = client.ikaClient;
	const suiClient = client.suiClient;
	const packageId = client.ref.packageId;
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, suiClient);
	const gasAddress = executor.address;

	const verifyIkaFee = params.verificationIkaFee ?? DEFAULT_VERIFY_IKA_FEE;
	const verifySuiFee = params.verificationSuiFee ?? DEFAULT_VERIFY_SUI_FEE;
	const reIkaFee = params.reEncryptIkaFee ?? DEFAULT_REENCRYPT_IKA_FEE;
	const reSuiFee = params.reEncryptSuiFee ?? DEFAULT_REENCRYPT_SUI_FEE;
	const timeoutMs = params.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const pollIntervalMs = params.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
	const progress = params.onProgress ?? (() => {});

	// ── prep: import-verification crypto + skip-already-registered check ──
	progress('preparing');
	const seed = params.solanaSecretKey.subarray(0, 32);
	const canonicalScalar = solanaSeedToCanonicalScalar(seed);
	const sessionIdBytes = createRandomSessionIdentifier();
	const importInput = await prepareImportedKeyDWalletVerification(
		ikaClient,
		Curve.ED25519,
		sessionIdBytes,
		gasAddress,
		params.importerEncryptionKeys,
		canonicalScalar,
	);
	const networkKey = await ikaClient.getLatestNetworkEncryptionKey();

	// Only key-holding members have an encryption identity to register; the
	// importer is always a key-holder (gated above) and approver-only members
	// are skipped here.
	const keyHolderKeys: UserShareEncryptionKeys[] = [
		params.importerEncryptionKeys,
		...params.nonImporterMembers
			.filter(
				(m): m is { kind: 'key-holder'; keys: UserShareEncryptionKeys } => m.kind === 'key-holder',
			)
			.map((m) => m.keys),
	];
	const alreadyRegistered = await Promise.all(
		keyHolderKeys.map(async (k) => {
			try {
				await ikaClient.getActiveEncryptionKey(k.getSuiAddress());
				return true;
			} catch {
				return false;
			}
		}),
	);

	// ── PTB 1: register every key-holder + verify import + create Recovery ──
	progress('creating');
	const createTx = new Transaction();

	// One IkaTransaction per key-holding member, all sharing the same
	// Transaction. Each .registerEncryptionKey() call signs with that member's
	// keys and adds a single Move call to the PTB.
	for (let i = 0; i < keyHolderKeys.length; i++) {
		if (alreadyRegistered[i]) continue;
		const ikaTxForMember = new IkaTransaction({
			ikaClient,
			transaction: createTx,
			userShareEncryptionKeys: keyHolderKeys[i],
		});
		await ikaTxForMember.registerEncryptionKey({ curve: Curve.ED25519 });
	}

	const importerIkaTx = new IkaTransaction({
		ikaClient,
		transaction: createTx,
		userShareEncryptionKeys: params.importerEncryptionKeys,
	});
	const sessionId = importerIkaTx.registerSessionIdentifier(sessionIdBytes);
	const verifyIkaCoin = coinWithBalance({
		balance: verifyIkaFee,
		type: client.ikaCoinType,
	});
	const verifySuiCoin = coinWithBalance({ balance: verifySuiFee });
	const importedKeyCap = await importerIkaTx.requestImportedKeyDWalletVerification({
		importDWalletVerificationRequestInput: importInput,
		curve: Curve.ED25519,
		signerPublicKey: params.importerEncryptionKeys.getSigningPublicKeyBytes(),
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
	createTx.transferObjects([verifyIkaCoin, verifySuiCoin], gasAddress);

	const createResult = await executor.signAndExecute(createTx);
	if (createResult.$kind !== 'Transaction') {
		throw new Error(
			`provisionInitialMembers.create: ${JSON.stringify(createResult.FailedTransaction.status)}`,
		);
	}
	const createDigest = createResult.Transaction.digest;

	const verifyEvent = createResult.Transaction.events.find((e) =>
		e.eventType.includes('DWalletImportedKeyVerificationRequestEvent'),
	);
	if (!verifyEvent?.bcs) {
		throw new Error(
			'provisionInitialMembers.create: DWalletImportedKeyVerificationRequestEvent missing',
		);
	}
	const verifyParsed = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.DWalletImportedKeyVerificationRequestEvent,
	).parse(new Uint8Array(verifyEvent.bcs));
	const dwalletId = verifyParsed.event_data.dwallet_id;
	const importerEncryptedUserShareId = verifyParsed.event_data.encrypted_user_secret_key_share_id;

	const recoveryObjectType = `${packageId}::recovery::Recovery`;
	const recoveryCreated = createResult.Transaction.effects.changedObjects.find(
		(c) =>
			c.idOperation === 'Created' &&
			createResult.Transaction.objectTypes[c.objectId] === recoveryObjectType,
	);
	if (!recoveryCreated) {
		throw new Error('provisionInitialMembers.create: Recovery object not in created objects');
	}
	const recoveryId = recoveryCreated.objectId;

	// ── wait for dWallet → AwaitingKeyHolderSignature so we can accept ──
	const awaitingDWallet = (await ikaClient.getDWalletInParticularState(
		dwalletId,
		'AwaitingKeyHolderSignature',
		{ timeout: timeoutMs, interval: pollIntervalMs },
	)) as ImportedKeyDWallet;

	// Track which non-importer slots are key-holders (need re-encrypt + accept)
	// vs approver-only (skipped). The original index lets us scatter result
	// share-ids back into a parallel-with-`nonImporterMembers` array later.
	const nonImporterKeyHolders: Array<{
		originalIndex: number;
		keys: UserShareEncryptionKeys;
	}> = [];
	for (let i = 0; i < params.nonImporterMembers.length; i++) {
		const slot = params.nonImporterMembers[i]!;
		if (slot.kind === 'key-holder') {
			nonImporterKeyHolders.push({ originalIndex: i, keys: slot.keys });
		}
	}

	// Fast path: every non-importer is approver-only. We only need PTB1 (the
	// importer's own accept-share is folded into PTB2 in the slow path; here we
	// do it as a tiny PTB-of-its-own and skip the re-encrypt + accept rounds).
	if (nonImporterKeyHolders.length === 0) {
		progress('accepting');
		const acceptOnlyTx = new Transaction();
		const acceptOnlyIkaTx = new IkaTransaction({
			ikaClient,
			transaction: acceptOnlyTx,
			userShareEncryptionKeys: params.importerEncryptionKeys,
		});
		await acceptOnlyIkaTx.acceptEncryptedUserShare({
			dWallet: awaitingDWallet,
			userPublicOutput: importInput.userPublicOutput,
			encryptedUserSecretKeyShareId: importerEncryptedUserShareId,
		});
		const acceptOnlyResult = await executor.signAndExecute(acceptOnlyTx);
		if (acceptOnlyResult.$kind !== 'Transaction') {
			throw new Error(
				`provisionInitialMembers.accept: ${JSON.stringify(acceptOnlyResult.FailedTransaction.status)}`,
			);
		}
		return {
			recoveryId,
			dwalletId,
			importerEncryptedUserShareId,
			nonImporterEncryptedUserShareIds: params.nonImporterMembers.map(() => null),
			txDigests: {
				create: createDigest,
				reEncrypt: null,
				accept: acceptOnlyResult.Transaction.digest,
			},
		};
	}

	// ── PTB 2: importer accept-share + re-encrypt for each key-holding non-importer ──
	progress('reEncrypting');
	const reTx = new Transaction();
	const acceptIkaTx = new IkaTransaction({
		ikaClient,
		transaction: reTx,
		userShareEncryptionKeys: params.importerEncryptionKeys,
	});
	await acceptIkaTx.acceptEncryptedUserShare({
		dWallet: awaitingDWallet,
		userPublicOutput: importInput.userPublicOutput,
		encryptedUserSecretKeyShareId: importerEncryptedUserShareId,
	});

	// The SDK's IkaTransaction.requestReEncryptUserShareFor would refuse to
	// build here because it checks the source share is already in
	// `KeyHolderSigned` state — but the accept-share command above only
	// mutates that state on-chain at runtime, atomically with this PTB. So we
	// call the lower-level coordinatorTransactions.requestReEncryptUserShareFor
	// directly and replicate the encryption + lookup the SDK wrapper does.
	//
	// To get the importer's plaintext user-secret-share before PTB2 executes,
	// we synthesize a post-accept view of the dWallet + source share that
	// satisfies `decryptUserShare`'s assertions. The user-output signature is
	// produced from the importer's signing key (which we hold) — the same
	// signature that the in-PTB acceptEncryptedUserShare command will post
	// on-chain a moment from now. The chain of trust is identical; we're
	// just running the verification a few hundred ms early.
	const protocolPublicParameters = await ikaClient.getProtocolPublicParameters(awaitingDWallet);
	const sourceShareAwaiting = await ikaClient.getEncryptedUserSecretKeyShare(
		importerEncryptedUserShareId,
	);
	const userOutputSignature = await params.importerEncryptionKeys.getUserOutputSignature(
		awaitingDWallet,
		importInput.userPublicOutput,
	);
	// accept-share commits the *network's* public_output (the one in
	// AwaitingKeyHolderSignature) into Active. The user_output_signature is
	// over that exact byte sequence — verifyAndGetDWalletDKGPublicOutput
	// verifies the signature against `state.Active.public_output`, so we
	// mirror what accept-share will write rather than substituting the
	// locally-computed userPublicOutput.
	const networkPublicOutput = awaitingDWallet.state.AwaitingKeyHolderSignature?.public_output;
	if (!networkPublicOutput) {
		throw new Error('provisionInitialMembers: AwaitingKeyHolderSignature.public_output missing');
	}
	const syntheticActiveDWallet = {
		...awaitingDWallet,
		state: {
			Active: { public_output: Array.from(networkPublicOutput) },
		},
	} as ImportedKeyDWallet;
	const syntheticKHSShare = {
		...sourceShareAwaiting,
		state: {
			KeyHolderSigned: {
				user_output_signature: Array.from(userOutputSignature),
			},
		},
	} as EncryptedUserSecretKeyShare;
	const { secretShare: importerSecretShare } = await params.importerEncryptionKeys.decryptUserShare(
		syntheticActiveDWallet,
		syntheticKHSShare,
		protocolPublicParameters,
	);

	for (const { keys: memberKeys } of nonImporterKeyHolders) {
		const memberAddress = memberKeys.getSuiAddress();
		const memberEncryptionObj = await ikaClient.getActiveEncryptionKey(memberAddress);
		const encryptedShareAndProof = await encryptSecretShare(
			Curve.ED25519,
			importerSecretShare,
			Uint8Array.from(memberEncryptionObj.encryption_key),
			protocolPublicParameters,
		);
		const reSessionIdBytes = createRandomSessionIdentifier();
		const reSessionArg = coordinatorTransactions.registerSessionIdentifier(
			ikaClient.ikaConfig,
			reTx.sharedObjectRef({
				objectId: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
				initialSharedVersion:
					ikaClient.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
				mutable: true,
			}),
			reSessionIdBytes,
			reTx,
		);
		const reIkaCoin = coinWithBalance({
			balance: reIkaFee,
			type: client.ikaCoinType,
		});
		const reSuiCoin = coinWithBalance({ balance: reSuiFee });
		coordinatorTransactions.requestReEncryptUserShareFor(
			ikaClient.ikaConfig,
			reTx.sharedObjectRef({
				objectId: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
				initialSharedVersion:
					ikaClient.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
				mutable: true,
			}),
			dwalletId,
			memberAddress,
			encryptedShareAndProof,
			importerEncryptedUserShareId,
			reSessionArg,
			reIkaCoin,
			reSuiCoin,
			reTx,
		);
		reTx.transferObjects([reIkaCoin, reSuiCoin], gasAddress);
	}

	const reResult = await executor.signAndExecute(reTx);
	if (reResult.$kind !== 'Transaction') {
		throw new Error(
			`provisionInitialMembers.reEncrypt: ${JSON.stringify(reResult.FailedTransaction.status)}`,
		);
	}
	const reDigest = reResult.Transaction.digest;

	// PTB2 emits one EncryptedShareVerificationRequestEvent per re-encrypt, in
	// order. Parse them to get each destination encrypted-share id.
	const reEvents = reResult.Transaction.events.filter((e) =>
		e.eventType.includes('EncryptedShareVerificationRequestEvent'),
	);
	if (reEvents.length !== nonImporterKeyHolders.length) {
		throw new Error(
			`provisionInitialMembers.reEncrypt: expected ${nonImporterKeyHolders.length} EncryptedShareVerificationRequestEvent, got ${reEvents.length}`,
		);
	}
	const keyHolderShareIds = reEvents.map((e) => {
		if (!e.bcs) {
			throw new Error('reEncrypt: event missing bcs payload');
		}
		return SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.EncryptedShareVerificationRequestEvent,
		).parse(new Uint8Array(e.bcs)).event_data.encrypted_user_secret_key_share_id;
	});

	// ── wait for every destination share's network verification ──
	progress('waitingVerification');
	const destShares = await Promise.all(
		keyHolderShareIds.map((id) =>
			ikaClient.getEncryptedUserSecretKeyShareInParticularState(
				id,
				'NetworkVerificationCompleted',
				{ timeout: timeoutMs, interval: pollIntervalMs },
			),
		),
	);

	// ── PTB 3: each key-holding non-importer accepts their re-encrypted share ──
	progress('accepting');
	// After PTB2, the dWallet is Active. Refresh once and re-fetch the source
	// share now that it carries the importer's KeyHolderSigned signature.
	const activeDWallet = (await ikaClient.getDWalletInParticularState(dwalletId, 'Active', {
		timeout: timeoutMs,
		interval: pollIntervalMs,
	})) as ImportedKeyDWallet;
	const sourceShareKHS = await ikaClient.getEncryptedUserSecretKeyShare(
		importerEncryptedUserShareId,
	);
	const sourceEncryptionKey = await fetchEncryptionKey(client, sourceShareKHS.encryption_key_id);

	const acceptTx = new Transaction();
	for (let i = 0; i < nonImporterKeyHolders.length; i++) {
		const ikaTxForMember = new IkaTransaction({
			ikaClient,
			transaction: acceptTx,
			userShareEncryptionKeys: nonImporterKeyHolders[i]!.keys,
		});
		await ikaTxForMember.acceptEncryptedUserShare({
			dWallet: activeDWallet,
			sourceEncryptionKey,
			sourceEncryptedUserSecretKeyShare: sourceShareKHS,
			destinationEncryptedUserSecretKeyShare: destShares[i]!,
		});
	}
	const acceptResult = await executor.signAndExecute(acceptTx);
	if (acceptResult.$kind !== 'Transaction') {
		throw new Error(
			`provisionInitialMembers.accept: ${JSON.stringify(acceptResult.FailedTransaction.status)}`,
		);
	}
	const acceptDigest = acceptResult.Transaction.digest;

	// Scatter the per-key-holder share-ids back into a parallel-with-
	// `nonImporterMembers` array, with `null` for approver-only slots.
	const nonImporterEncryptedUserShareIds: Array<string | null> = params.nonImporterMembers.map(
		() => null,
	);
	for (let i = 0; i < nonImporterKeyHolders.length; i++) {
		nonImporterEncryptedUserShareIds[nonImporterKeyHolders[i]!.originalIndex] =
			keyHolderShareIds[i]!;
	}

	return {
		recoveryId,
		dwalletId,
		importerEncryptedUserShareId,
		nonImporterEncryptedUserShareIds,
		txDigests: {
			create: createDigest,
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
			`provisionInitialMembers.fetchEncryptionKey: object ${encryptionKeyId} returned no content`,
		);
	}
	return CoordinatorInnerModule.EncryptionKey.parse(object.content) as EncryptionKey;
}

// Suppress unused-import lint when types are only re-exported.
export type { EncryptedUserSecretKeyShare };
