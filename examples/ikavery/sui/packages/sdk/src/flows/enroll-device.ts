import {
	CoordinatorInnerModule,
	Curve,
	encryptSecretShare,
	IkaTransaction,
	SessionsManagerModule,
	type EncryptedUserSecretKeyShare,
	type EncryptionKey,
	type ImportedKeyDWallet,
	type UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import { bcs } from '@mysten/sui/bcs';
import type { Keypair } from '@mysten/sui/cryptography';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';

import type { RecoveryClient } from '../client';
import { buildEnrollApproveChallenge, buildEnrollProposeChallenge } from '../crypto/challenges';
import { executorFromKeypair, type TransactionExecutor } from '../executor';
import * as moveRecovery from '../generated/recovery/recovery';
import { buildCredential, type AuthSigner } from '../move/credential';
import { memberIdBytes, newMemberToMoveArg, type NewMemberInput } from '../move/members';
import { readRecoveryState } from './state';

const DEFAULT_IKA_FEE = 1_000_000n;
const DEFAULT_SUI_FEE = 1_000_000n;
const DEFAULT_TIMEOUT_MS = 600_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;

// ===== registerDeviceEncryptionKey =====

export interface RegisterDeviceEncryptionKeyParams {
	userShareEncryptionKeys: UserShareEncryptionKeys;
	gasSigner: Keypair | TransactionExecutor;
}

/**
 * One-time per device: register the new device's class-groups encryption key
 * on Ika so existing members can re-encrypt the user share to it. Must be
 * called before `proposeEnrollment` references this device's encryption-key
 * Sui address.
 *
 * Idempotent — if the encryption key is already registered for this device's
 * Sui address (e.g. on a re-run after a partial failure), this is a no-op.
 * Returns `{ digest: null }` in that case.
 */
export async function registerDeviceEncryptionKey(
	client: RecoveryClient,
	params: RegisterDeviceEncryptionKeyParams,
): Promise<{ digest: string | null }> {
	try {
		await client.ikaClient.getActiveEncryptionKey(params.userShareEncryptionKeys.getSuiAddress());
		return { digest: null };
	} catch {
		/* not registered yet — proceed below */
	}

	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);

	const tx = new Transaction();
	const ikaTx = new IkaTransaction({
		ikaClient: client.ikaClient,
		transaction: tx,
		userShareEncryptionKeys: params.userShareEncryptionKeys,
	});
	await ikaTx.registerEncryptionKey({ curve: Curve.ED25519 });
	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(
			`registerDeviceEncryptionKey: failed: ${JSON.stringify(result.FailedTransaction.status)}`,
		);
	}
	return { digest: result.Transaction.digest };
}

// ===== proposeEnrollment =====

export interface ProposeEnrollmentParams {
	/** Identity to add as a member, scheme + public key. */
	newMember: NewMemberInput;
	/**
	 * Sui address of the new device's `UserShareEncryptionKeys`, returned by
	 * `deriveDeviceIdentity(...).encryptionKeySuiAddress`. Must already be
	 * registered on Ika via `registerDeviceEncryptionKey`. For approver-only
	 * (`sender_address`) members, pass `@0x0` — Move ignores the field for
	 * that variant.
	 */
	newEncryptionKeyAddress: string;
	/**
	 * Caller's auth — proves the proposer is an existing member. Signs a
	 * challenge bound to `(recoveryId, newMemberId, currentNonce)`.
	 */
	authSigner: AuthSigner;
	gasSigner: Keypair | TransactionExecutor;
}

export interface ProposeEnrollmentResult {
	enrollmentId: bigint;
	digest: string;
}

export async function proposeEnrollment(
	client: RecoveryClient,
	params: ProposeEnrollmentParams,
): Promise<ProposeEnrollmentResult> {
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);
	const state = await readRecoveryState(client);

	const challenge = buildEnrollProposeChallenge(
		client.ref.recoveryId,
		memberIdBytes(params.newMember),
		state.nonce,
	);
	const credentialInput = await params.authSigner.sign(challenge);

	const tx = new Transaction();
	const newMemberArg = newMemberToMoveArg(tx, client.ref.packageId, params.newMember);
	const credArg = buildCredential(tx, client.ref.packageId, credentialInput);

	client.move.proposeEnrollment({
		self: client.ref.recoveryId,
		newMember: newMemberArg,
		newEncryptionKeyAddress: params.newEncryptionKeyAddress,
		cred: credArg,
	})(tx);

	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(
			`proposeEnrollment: failed: ${JSON.stringify(result.FailedTransaction.status)}`,
		);
	}
	return {
		enrollmentId: state.nextEnrollmentId,
		digest: result.Transaction.digest,
	};
}

// ===== approveEnrollment =====

export interface ApproveEnrollmentParams {
	enrollmentId: bigint;
	authSigner: AuthSigner;
	gasSigner: Keypair | TransactionExecutor;
}

export async function approveEnrollment(
	client: RecoveryClient,
	params: ApproveEnrollmentParams,
): Promise<{ digest: string }> {
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);
	const challenge = buildEnrollApproveChallenge(client.ref.recoveryId, params.enrollmentId);
	const credentialInput = await params.authSigner.sign(challenge);

	const tx = new Transaction();
	const credArg = buildCredential(tx, client.ref.packageId, credentialInput);
	client.move.approveEnrollment({
		self: client.ref.recoveryId,
		enrollmentId: params.enrollmentId,
		cred: credArg,
	})(tx);

	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(
			`approveEnrollment: failed: ${JSON.stringify(result.FailedTransaction.status)}`,
		);
	}
	return { digest: result.Transaction.digest };
}

// ===== executeEnrollment =====

export interface ExecuteEnrollmentParams {
	enrollmentId: bigint;
	/**
	 * Encryption identity of the executor. Must hold a decryptable share for
	 * the recovery's imported-key dWallet — i.e. the executor is already an
	 * enrolled member.
	 */
	userShareEncryptionKeys: UserShareEncryptionKeys;
	/**
	 * The executor's `EncryptedUserSecretKeyShare` (from `getEncryptedUserSecretKeyShare`).
	 * Used both as the source for re-encryption and to pass `source_encrypted_user_secret_key_share_id` to Move.
	 */
	sourceEncryptedUserShare: EncryptedUserSecretKeyShare;
	/** Sui address of the new device's `UserShareEncryptionKeys`. */
	newEncryptionKeyAddress: string;
	gasSigner: Keypair | TransactionExecutor;
	ikaFee?: bigint;
	suiFee?: bigint;
}

export interface ExecuteEnrollmentResult {
	digest: string;
	/**
	 * The destination encrypted-share object id, parsed from the
	 * `EncryptedShareVerificationRequestEvent` emitted by the coordinator. Used
	 * by the new device's `acceptEnrollment` step.
	 */
	destEncryptedUserShareId: string;
}

export async function executeEnrollment(
	client: RecoveryClient,
	params: ExecuteEnrollmentParams,
): Promise<ExecuteEnrollmentResult> {
	const ikaClient = client.ikaClient;
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);

	const dWallet = (await ikaClient.getDWalletInParticularState(
		(await readRecoveryState(client)).importedKeyDwalletId,
		'Active',
	)) as ImportedKeyDWallet;

	const publicParameters = await ikaClient.getProtocolPublicParameters(dWallet);
	const destEncryptionKeyObj = await ikaClient.getActiveEncryptionKey(
		params.newEncryptionKeyAddress,
	);

	// Decrypt the executor's own share, then re-encrypt to the destination's
	// class-groups public key. This produces the ciphertext + ZK proof the Move
	// function forwards to coordinator::request_re_encrypt_user_share_for.
	const { secretShare } = await params.userShareEncryptionKeys.decryptUserShare(
		dWallet,
		params.sourceEncryptedUserShare,
		publicParameters,
	);
	const encryptedShareAndProof = await encryptSecretShare(
		Curve.ED25519,
		secretShare,
		Uint8Array.from(destEncryptionKeyObj.encryption_key),
		publicParameters,
	);

	const tx = new Transaction();
	const ikaCoin = coinWithBalance({
		balance: params.ikaFee ?? DEFAULT_IKA_FEE,
		type: client.ikaCoinType,
	});
	const suiCoin = coinWithBalance({
		balance: params.suiFee ?? DEFAULT_SUI_FEE,
	});
	client.move.executeEnrollment({
		self: client.ref.recoveryId,
		coord: ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
		enrollmentId: params.enrollmentId,
		encryptedCentralizedSecretShareAndProof: Array.from(encryptedShareAndProof),
		sourceEncryptedUserSecretKeyShareId: params.sourceEncryptedUserShare.id,
		registry: tx.object(client.ref.registryId),
		ika: ikaCoin,
		sui: suiCoin,
	})(tx);
	tx.transferObjects([ikaCoin, suiCoin], executor.address);

	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(
			`executeEnrollment: failed: ${JSON.stringify(result.FailedTransaction.status)}`,
		);
	}
	const ev = result.Transaction.events.find((e) =>
		e.eventType.includes('EncryptedShareVerificationRequestEvent'),
	);
	if (!ev?.bcs) {
		throw new Error(
			'executeEnrollment: EncryptedShareVerificationRequestEvent missing from execute-tx events',
		);
	}
	const parsed = SessionsManagerModule.DWalletSessionEvent(
		CoordinatorInnerModule.EncryptedShareVerificationRequestEvent,
	).parse(new Uint8Array(ev.bcs));
	return {
		digest: result.Transaction.digest,
		destEncryptedUserShareId: parsed.event_data.encrypted_user_secret_key_share_id,
	};
}

// ===== executeApproverOnlyEnrollment =====

export interface ExecuteApproverOnlyEnrollmentParams {
	enrollmentId: bigint;
	gasSigner: Keypair | TransactionExecutor;
}

/**
 * Execute an enrollment whose new member is `sender_address` (approver-only).
 * Skips the share re-encryption entirely — the new member doesn't hold a
 * share, so there's nothing to re-encrypt. After this returns, the new
 * member can propose + approve but cannot execute (their action attempts
 * would be rejected by `recovery::execute`'s `EApproverOnly` gate).
 *
 * Use this in place of `executeEnrollment` when
 * `proposeEnrollment` was called with a `sender_address` `newMember`.
 */
export async function executeApproverOnlyEnrollment(
	client: RecoveryClient,
	params: ExecuteApproverOnlyEnrollmentParams,
): Promise<{ digest: string }> {
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);
	const tx = new Transaction();
	client.move.executeEnrollmentApproverOnly({
		self: client.ref.recoveryId,
		enrollmentId: params.enrollmentId,
		registry: tx.object(client.ref.registryId),
	})(tx);
	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(
			`executeApproverOnlyEnrollment: failed: ${JSON.stringify(result.FailedTransaction.status)}`,
		);
	}
	return { digest: result.Transaction.digest };
}

// ===== acceptEnrollment =====

export interface AcceptEnrollmentParams {
	/** New device's encryption identity (the same one passed to register/propose). */
	userShareEncryptionKeys: UserShareEncryptionKeys;
	/**
	 * The destination `EncryptedUserSecretKeyShare` id, returned by `executeEnrollment`.
	 * The new device polls it to `NetworkVerificationCompleted`, then signs the
	 * accept-share PTB with its own keypair so Ika records the share as owned.
	 */
	destEncryptedUserShareId: string;
	gasSigner: Keypair;
	timeoutMs?: number;
	pollIntervalMs?: number;
}

export async function acceptEnrollment(
	client: RecoveryClient,
	params: AcceptEnrollmentParams,
): Promise<{ digest: string }> {
	const ikaClient = client.ikaClient;
	const state = await readRecoveryState(client);

	// Wait for the destination encrypted share to finish network verification.
	const destEncShare = await ikaClient.getEncryptedUserSecretKeyShareInParticularState(
		params.destEncryptedUserShareId,
		'NetworkVerificationCompleted',
		{
			timeout: params.timeoutMs ?? DEFAULT_TIMEOUT_MS,
			interval: params.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
		},
	);

	if (!destEncShare.source_encrypted_user_secret_key_share_id) {
		throw new Error(
			'acceptEnrollment: destination share has no source — wrong path for first import?',
		);
	}
	const srcEncShare = await ikaClient.getEncryptedUserSecretKeyShare(
		destEncShare.source_encrypted_user_secret_key_share_id,
	);
	const srcEncryptionKey = await fetchEncryptionKey(client, srcEncShare.encryption_key_id);

	const dWallet = (await ikaClient.getDWalletInParticularState(
		state.importedKeyDwalletId,
		'Active',
	)) as ImportedKeyDWallet;

	const tx = new Transaction();
	const ikaTx = new IkaTransaction({
		ikaClient,
		transaction: tx,
		userShareEncryptionKeys: params.userShareEncryptionKeys,
	});
	await ikaTx.acceptEncryptedUserShare({
		dWallet,
		sourceEncryptionKey: srcEncryptionKey,
		sourceEncryptedUserSecretKeyShare: srcEncShare,
		destinationEncryptedUserSecretKeyShare: destEncShare,
	});

	const result = await client.suiClient.core.signAndExecuteTransaction({
		transaction: tx,
		signer: params.gasSigner,
	});
	if (result.$kind !== 'Transaction') {
		throw new Error(`acceptEnrollment: failed: ${JSON.stringify(result.FailedTransaction.status)}`);
	}
	return { digest: result.Transaction.digest };
}

// ===== readEnrollment / listEnrollmentSnapshots =====

export type EnrollmentNewMemberKind =
	| { kind: 'ed25519'; publicKey: Uint8Array }
	| { kind: 'secp256k1'; publicKey: Uint8Array }
	| { kind: 'secp256r1'; publicKey: Uint8Array }
	| { kind: 'webauthn'; publicKey: Uint8Array }
	| { kind: 'sender_address'; address: string };

export interface EnrollmentSnapshot {
	enrollmentId: bigint;
	/** Decoded `NewMember` so the UI can render the proposed identity. */
	newMember: EnrollmentNewMemberKind;
	newEncryptionKeyAddress: string;
	approvals: bigint;
	voters: Uint8Array[];
	executed: boolean;
	/** True for `sender_address` — needs `executeApproverOnlyEnrollment`. */
	approverOnly: boolean;
}

export async function readEnrollment(
	client: RecoveryClient,
	enrollmentId: bigint,
): Promise<EnrollmentSnapshot> {
	const state = await readRecoveryState(client);
	const { dynamicField } = await client.suiClient.core.getDynamicField({
		parentId: state.enrollmentsTableId,
		name: { type: 'u64', bcs: bcs.u64().serialize(enrollmentId).toBytes() },
	});
	const raw = moveRecovery.EnrollmentProposal.parse(dynamicField.value.bcs);
	const newMember = decodeEnrollmentNewMember(raw.new_member);
	return {
		enrollmentId,
		newMember,
		newEncryptionKeyAddress: raw.new_encryption_key_address,
		approvals: BigInt(raw.approvals),
		voters: raw.voters.contents.map((b) => Uint8Array.from(b)),
		executed: raw.executed,
		approverOnly: newMember.kind === 'sender_address',
	};
}

/**
 * Best-effort enumeration: scans `[0..nextEnrollmentId)` and returns each
 * snapshot. Skips ids that don't resolve (deleted by `recovery::cleanup`
 * after a successful execute, etc.).
 */
export async function listEnrollmentSnapshots(
	client: RecoveryClient,
): Promise<EnrollmentSnapshot[]> {
	const state = await readRecoveryState(client);
	const out: EnrollmentSnapshot[] = [];
	for (let i = 0n; i < state.nextEnrollmentId; i++) {
		try {
			out.push(await readEnrollment(client, i));
		} catch {
			// missing dynamic field — already cleaned up
		}
	}
	return out;
}

function decodeEnrollmentNewMember(
	raw: { $kind: string } & Record<string, unknown>,
): EnrollmentNewMemberKind {
	// The generated enum surfaces as `{ $kind: "Ed25519", Ed25519: number[] }`
	// etc. — same shape as `auth.NewMember`'s BCS variants.
	switch (raw.$kind) {
		case 'Ed25519':
			return {
				kind: 'ed25519',
				publicKey: Uint8Array.from(raw.Ed25519 as number[]),
			};
		case 'Secp256k1':
			return {
				kind: 'secp256k1',
				publicKey: Uint8Array.from(raw.Secp256k1 as number[]),
			};
		case 'Secp256r1':
			return {
				kind: 'secp256r1',
				publicKey: Uint8Array.from(raw.Secp256r1 as number[]),
			};
		case 'WebAuthn':
			return {
				kind: 'webauthn',
				publicKey: Uint8Array.from(raw.WebAuthn as number[]),
			};
		case 'SenderAddress':
			return { kind: 'sender_address', address: raw.SenderAddress as string };
		default:
			throw new Error(`unknown NewMember variant: ${raw.$kind}`);
	}
}

// ===== internals =====

async function fetchEncryptionKey(
	client: RecoveryClient,
	encryptionKeyId: string,
): Promise<EncryptionKey> {
	const { object } = await client.suiClient.core.getObject({
		objectId: encryptionKeyId,
		include: { content: true },
	});
	if (!object.content) {
		throw new Error(`fetchEncryptionKey: object ${encryptionKeyId} returned no content`);
	}
	return CoordinatorInnerModule.EncryptionKey.parse(object.content) as EncryptionKey;
}

// Suppress the unused-import warning when this file is imported only for its
// side-effect-free types in some build configs.
export type { AuthSigner };
