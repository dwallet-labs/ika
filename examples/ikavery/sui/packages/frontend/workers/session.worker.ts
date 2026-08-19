/// <reference lib="webworker" />

import type { NewMemberInput } from '@fesal-packages/ikavery-sui-sdk';
import {
	approveEnrollment,
	approveRecovery,
	approveRosterChange,
	executeApproverOnlyEnrollment,
	executeEnrollment,
	executeRecovery,
	executeRosterChange,
	getGrpcFullnodeUrl,
	importSolanaKey,
	proposeEnrollment,
	proposeRecovery,
	proposeRosterChange,
	provisionInitialMembers,
	RecoveryClient,
	registerDeviceEncryptionKey,
	type AuthSigner,
	type CredentialInput,
	type TransactionExecuteResult,
	type TransactionExecutor,
} from '@fesal-packages/ikavery-sui-sdk';
import { getNetworkConfig, IkaClient, UserShareEncryptionKeys } from '@ika.xyz/sdk';
import type { ClientWithCoreApi } from '@mysten/sui/client';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Transaction } from '@mysten/sui/transactions';

export interface SessionConfig {
	network: 'testnet' | 'mainnet';
	rpcUrl: string;
	recoveryPackageId: string;
	recoveryRegistryId: string;
	rpId: string;
}

/**
 * Identity blob describing how the main thread should produce a credential
 * for a given operation challenge. The worker can't run WebAuthn or talk to
 * a wallet directly, so it sends one of these to main thread alongside the
 * challenge and waits for a `CredentialInput` back.
 */
export type AuthIdentity =
	| {
			kind: 'passkey';
			credentialIdHex: string;
			/** Compressed P-256 (33 bytes) for the WebAuthn member. */
			publicKeyHex: string;
	  }
	| {
			kind: 'wallet';
			/** Sui address whose `signPersonalMessage` produces the auth signature. */
			address: string;
	  }
	| {
			kind: 'approver';
			/**
			 * Sui address of an approver-only member (scheme `sender_address`).
			 * Authorization is by ctx.sender match — no challenge sig needed.
			 */
			address: string;
	  };

export type AdditionalMember =
	{ kind: 'key-holder'; keyBytes: Uint8Array } | { kind: 'approver-only' };

export interface ImportKeyArgs {
	/** Sui address that pays gas + becomes ctx.sender for every PTB. */
	walletAddress: string;
	/**
	 * Importer's serialized `UserShareEncryptionKeys`. Captured during
	 * /setup/connect either by passkey-PRF derivation or by hashing a wallet
	 * personal-message signature.
	 */
	importerKeyBytes: Uint8Array;
	solanaSecretKey: Uint8Array;
	initialMembers: NewMemberInput[];
	threshold: number;
	/**
	 * Per-non-importer-member info, parallel to the non-importer slice of
	 * `initialMembers`. Key-holders carry serialized `UserShareEncryptionKeys`
	 * for the in-PTB re-encrypt; approver-only entries carry no key bytes.
	 */
	additionalMembers: AdditionalMember[];
	verificationIkaFee: bigint;
	verificationSuiFee: bigint;
}

export interface ImportKeyResult {
	recoveryId: string;
	dwalletId: string;
	encryptedUserShareId: string;
	txDigest: string;
	/**
	 * Per-non-importer-member: the destination encrypted-share id created by
	 * the re-encryption + accept fan-out.
	 */
	provisioned: { destEncryptedUserShareId: string }[];
}

export type ImportKeyPhase = 'preparing' | 'verifying' | 'accepting' | 'provisioning';

export type ExecuteRecoveryPhaseDTO =
	| 'reading-proposal'
	| 'fetching-blockhash'
	| 'decrypting-share'
	| 'waiting-for-presigns'
	| 'building-signatures'
	| 'auth-ceremony'
	| 'submitting-execute'
	| 'waiting-for-sign-sessions'
	| 'assembling';

export interface ProposeRecoveryArgs {
	/** Sui address that pays gas + becomes ctx.sender for the propose PTB. */
	walletAddress: string;
	/** Shared object id of the recovery this proposal belongs to. */
	recoveryId: string;
	/** Solana sweep messages, in execution order. */
	sweepMessages: Uint8Array[];
	/** Identity that signs the propose challenge. */
	authIdentity: AuthIdentity;
}

export interface ProposeRecoveryResultDTO {
	proposalId: string;
	digest: string;
	intentHashHex: string;
}

export interface ApproveRecoveryArgs {
	walletAddress: string;
	recoveryId: string;
	proposalId: string;
	authIdentity: AuthIdentity;
}

export interface ApproveRecoveryResultDTO {
	digest: string;
}

export interface ExecuteRecoveryArgs {
	walletAddress: string;
	recoveryId: string;
	proposalId: string;
	/** Executor's serialized `UserShareEncryptionKeys` (decrypts the share). */
	importerKeyBytes: Uint8Array;
	encryptedUserShareId: string;
	solanaRpcUrl: string;
	authIdentity: AuthIdentity;
	ikaFeePerMessage: bigint;
	suiFeePerMessage: bigint;
}

export interface ExecuteRecoveryResultDTO {
	digest: string;
	signedTransactions: Uint8Array[];
	signIds: string[];
}

export interface ProposeEnrollmentArgs {
	walletAddress: string;
	recoveryId: string;
	newMember: NewMemberInput;
	/** `@0x0` for approver-only members. */
	newEncryptionKeyAddress: string;
	authIdentity: AuthIdentity;
}

export interface ProposeEnrollmentResultDTO {
	enrollmentId: string;
	digest: string;
}

export interface ApproveEnrollmentArgs {
	walletAddress: string;
	recoveryId: string;
	enrollmentId: string;
	authIdentity: AuthIdentity;
}

export interface ApproveEnrollmentResultDTO {
	digest: string;
}

export interface ExecuteApproverEnrollmentArgs {
	walletAddress: string;
	recoveryId: string;
	enrollmentId: string;
}

export interface ExecuteApproverEnrollmentResultDTO {
	digest: string;
}

export interface ExecuteKeyHolderEnrollmentArgs {
	walletAddress: string;
	recoveryId: string;
	enrollmentId: string;
	/** Executor's serialized `UserShareEncryptionKeys` (decrypts the share). */
	importerKeyBytes: Uint8Array;
	/** Executor's encrypted-user-share id on chain (source for re-encryption). */
	encryptedUserShareId: string;
	/** New member's encryption-key Sui address. */
	newEncryptionKeyAddress: string;
}

export interface ExecuteKeyHolderEnrollmentResultDTO {
	digest: string;
	destEncryptedUserShareId: string;
}

export interface RegisterDeviceEncryptionKeyArgs {
	walletAddress: string;
	/** Serialized `UserShareEncryptionKeys` for the new device. */
	newDeviceKeyBytes: Uint8Array;
}

export interface RegisterDeviceEncryptionKeyResultDTO {
	/** Null when the encryption key was already registered (idempotent). */
	digest: string | null;
}

export interface ProposeRosterChangeArgs {
	walletAddress: string;
	recoveryId: string;
	/** Canonical member ids to remove (`[scheme, ...pubkey/addr]` shape). */
	membersToRemove: Uint8Array[];
	/** `null` to keep current threshold; bigint serialized as decimal string. */
	newThreshold: string | null;
	authIdentity: AuthIdentity;
}

export interface ProposeRosterChangeResultDTO {
	rosterChangeId: string;
	digest: string;
}

export interface ApproveRosterChangeArgs {
	walletAddress: string;
	recoveryId: string;
	rosterChangeId: string;
	authIdentity: AuthIdentity;
}

export interface ApproveRosterChangeResultDTO {
	digest: string;
}

export interface ExecuteRosterChangeArgs {
	walletAddress: string;
	recoveryId: string;
	rosterChangeId: string;
}

export interface ExecuteRosterChangeResultDTO {
	digest: string;
}

export type SessionCommand =
	| { type: 'init'; id: number; config: SessionConfig }
	| { type: 'importSolanaKey'; id: number; args: ImportKeyArgs }
	| { type: 'proposeRecovery'; id: number; args: ProposeRecoveryArgs }
	| { type: 'approveRecovery'; id: number; args: ApproveRecoveryArgs }
	| { type: 'executeRecovery'; id: number; args: ExecuteRecoveryArgs }
	| { type: 'proposeEnrollment'; id: number; args: ProposeEnrollmentArgs }
	| { type: 'approveEnrollment'; id: number; args: ApproveEnrollmentArgs }
	| {
			type: 'executeApproverEnrollment';
			id: number;
			args: ExecuteApproverEnrollmentArgs;
	  }
	| {
			type: 'executeKeyHolderEnrollment';
			id: number;
			args: ExecuteKeyHolderEnrollmentArgs;
	  }
	| {
			type: 'registerDeviceEncryptionKey';
			id: number;
			args: RegisterDeviceEncryptionKeyArgs;
	  }
	| { type: 'proposeRosterChange'; id: number; args: ProposeRosterChangeArgs }
	| { type: 'approveRosterChange'; id: number; args: ApproveRosterChangeArgs }
	| { type: 'executeRosterChange'; id: number; args: ExecuteRosterChangeArgs }
	| {
			type: 'signResponse';
			id: number;
			ok: true;
			result: TransactionExecuteResult;
	  }
	| { type: 'signResponse'; id: number; ok: false; error: string }
	| {
			type: 'credentialResponse';
			id: number;
			ok: true;
			credential: CredentialInput;
	  }
	| { type: 'credentialResponse'; id: number; ok: false; error: string };

export type SessionEvent =
	| { type: 'ready'; id: number }
	| { type: 'error'; id: number; error: string }
	| {
			type: 'progress';
			id: number;
			phase: ImportKeyPhase;
			detail?: string;
	  }
	| {
			type: 'executeProgress';
			id: number;
			phase: ExecuteRecoveryPhaseDTO;
			index?: number;
			total?: number;
	  }
	| { type: 'result'; id: number; result: ImportKeyResult }
	| { type: 'proposeResult'; id: number; result: ProposeRecoveryResultDTO }
	| { type: 'approveResult'; id: number; result: ApproveRecoveryResultDTO }
	| { type: 'executeResult'; id: number; result: ExecuteRecoveryResultDTO }
	| {
			type: 'proposeEnrollmentResult';
			id: number;
			result: ProposeEnrollmentResultDTO;
	  }
	| {
			type: 'approveEnrollmentResult';
			id: number;
			result: ApproveEnrollmentResultDTO;
	  }
	| {
			type: 'executeApproverEnrollmentResult';
			id: number;
			result: ExecuteApproverEnrollmentResultDTO;
	  }
	| {
			type: 'executeKeyHolderEnrollmentResult';
			id: number;
			result: ExecuteKeyHolderEnrollmentResultDTO;
	  }
	| {
			type: 'registerDeviceEncryptionKeyResult';
			id: number;
			result: RegisterDeviceEncryptionKeyResultDTO;
	  }
	| {
			type: 'proposeRosterChangeResult';
			id: number;
			result: ProposeRosterChangeResultDTO;
	  }
	| {
			type: 'approveRosterChangeResult';
			id: number;
			result: ApproveRosterChangeResultDTO;
	  }
	| {
			type: 'executeRosterChangeResult';
			id: number;
			result: ExecuteRosterChangeResultDTO;
	  }
	| { type: 'signRequest'; id: number; jobId: number; txJson: string }
	| {
			type: 'credentialRequest';
			id: number;
			jobId: number;
			challenge: Uint8Array;
			identity: AuthIdentity;
	  };

const ctx = self as DedicatedWorkerGlobalScope;
let ikaClient: IkaClient | null = null;
let suiClient: ClientWithCoreApi | null = null;
let recoveryClient: RecoveryClient | null = null;
let initPromise: Promise<void> | null = null;

async function ensureInit(config: SessionConfig): Promise<void> {
	if (recoveryClient) return;
	if (initPromise) return initPromise;
	initPromise = (async () => {
		const url = config.rpcUrl || getGrpcFullnodeUrl(config.network);
		suiClient = new SuiGrpcClient({ baseUrl: url, network: config.network });
		ikaClient = new IkaClient({
			suiClient,
			config: getNetworkConfig(config.network),
			cache: true,
		});
		await ikaClient.initialize();
		recoveryClient = new RecoveryClient({
			ikaClient,
			suiClient,
			ref: {
				packageId: config.recoveryPackageId,
				recoveryId: '0x0',
				registryId: config.recoveryRegistryId,
			},
			rpId: config.rpId,
		});
	})();
	await initPromise;
}

let nextSignId = 1;
const pendingSign = new Map<
	number,
	{
		resolve: (r: TransactionExecuteResult) => void;
		reject: (e: Error) => void;
	}
>();

let nextCredId = 1;
const pendingCred = new Map<
	number,
	{
		resolve: (c: CredentialInput) => void;
		reject: (e: Error) => void;
	}
>();

function bridgeAuthSigner(jobId: number, identity: AuthIdentity): AuthSigner {
	return {
		sign(challenge) {
			// Approver-only members authenticate by ctx.sender match — no challenge
			// signature exists, the credential is the address itself.
			if (identity.kind === 'approver') {
				return Promise.resolve<CredentialInput>({
					scheme: 'sender_address',
					address: identity.address,
				});
			}
			const id = nextCredId++;
			const promise = new Promise<CredentialInput>((resolve, reject) => {
				pendingCred.set(id, { resolve, reject });
			});
			const ev: SessionEvent = {
				type: 'credentialRequest',
				id,
				jobId,
				challenge,
				identity,
			};
			ctx.postMessage(ev);
			return promise;
		},
	};
}

function makeMainThreadExecutor(walletAddress: string, jobId: number): TransactionExecutor {
	return {
		address: walletAddress,
		async signAndExecute(transaction) {
			transaction.setSender(walletAddress);
			if (!suiClient) throw new Error('Sui client not initialized');
			const txJson = await transaction.toJSON({ client: suiClient });
			const id = nextSignId++;
			const promise = new Promise<TransactionExecuteResult>((resolve, reject) => {
				pendingSign.set(id, { resolve, reject });
			});
			const ev: SessionEvent = {
				type: 'signRequest',
				id,
				jobId,
				txJson,
			};
			ctx.postMessage(ev);
			return await promise;
		},
	};
}

function bytesToHex(b: Uint8Array): string {
	return Array.from(b)
		.map((x) => x.toString(16).padStart(2, '0'))
		.join('');
}

/** Build a fresh RecoveryClient bound to a specific recoveryId. */
function makeProposalClient(recoveryId: string): RecoveryClient {
	if (!ikaClient || !suiClient || !recoveryClient)
		throw new Error('session worker not initialized');
	return new RecoveryClient({
		ikaClient,
		suiClient,
		ref: {
			packageId: recoveryClient.ref.packageId,
			recoveryId,
			registryId: recoveryClient.ref.registryId,
		},
		rpId: recoveryClient.rpId,
	});
}

ctx.addEventListener('message', async (e: MessageEvent<SessionCommand>) => {
	const cmd = e.data;

	if (cmd.type === 'signResponse') {
		const job = pendingSign.get(cmd.id);
		if (!job) return;
		pendingSign.delete(cmd.id);
		if (cmd.ok) job.resolve(cmd.result);
		else job.reject(new Error(cmd.error));
		return;
	}

	if (cmd.type === 'credentialResponse') {
		const job = pendingCred.get(cmd.id);
		if (!job) return;
		pendingCred.delete(cmd.id);
		if (cmd.ok) job.resolve(cmd.credential);
		else job.reject(new Error(cmd.error));
		return;
	}

	try {
		switch (cmd.type) {
			case 'init': {
				await ensureInit(cmd.config);
				const ev: SessionEvent = { type: 'ready', id: cmd.id };
				ctx.postMessage(ev);
				return;
			}
			case 'importSolanaKey': {
				if (!recoveryClient || !ikaClient) throw new Error('session worker not initialized');

				const post = (phase: ImportKeyPhase, detail?: string): void => {
					const ev: SessionEvent = {
						type: 'progress',
						id: cmd.id,
						phase,
						detail,
					};
					ctx.postMessage(ev);
				};

				const importerKeys = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
					cmd.args.importerKeyBytes,
				);

				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);

				const additionalMembers = cmd.args.additionalMembers;

				// Importer-only fast path: skip the multi-PTB provisioning flow.
				if (additionalMembers.length === 0) {
					post('preparing');
					post('verifying');
					const importResult = await importSolanaKey(recoveryClient, {
						solanaSecretKey: cmd.args.solanaSecretKey,
						userShareEncryptionKeys: importerKeys,
						gasSigner: executor,
						initialMembers: cmd.args.initialMembers,
						threshold: cmd.args.threshold,
						verificationIkaFee: cmd.args.verificationIkaFee,
						verificationSuiFee: cmd.args.verificationSuiFee,
					});
					post('accepting');
					const ev: SessionEvent = {
						type: 'result',
						id: cmd.id,
						result: {
							recoveryId: importResult.recoveryId,
							dwalletId: importResult.dwalletId,
							encryptedUserShareId: importResult.encryptedUserShareId,
							txDigest: importResult.txDigests.create,
							provisioned: [],
						},
					};
					ctx.postMessage(ev);
					return;
				}

				const nonImporterMembers = additionalMembers.map((m) =>
					m.kind === 'key-holder'
						? {
								kind: 'key-holder' as const,
								keys: UserShareEncryptionKeys.fromShareEncryptionKeysBytes(m.keyBytes),
							}
						: { kind: 'approver-only' as const },
				);

				const result = await provisionInitialMembers(recoveryClient, {
					solanaSecretKey: cmd.args.solanaSecretKey,
					importerEncryptionKeys: importerKeys,
					nonImporterMembers,
					initialMembers: cmd.args.initialMembers,
					threshold: cmd.args.threshold,
					gasSigner: executor,
					verificationIkaFee: cmd.args.verificationIkaFee,
					verificationSuiFee: cmd.args.verificationSuiFee,
					onProgress: (phase) => {
						const map: Record<string, ImportKeyPhase> = {
							preparing: 'preparing',
							creating: 'verifying',
							reEncrypting: 'provisioning',
							waitingVerification: 'provisioning',
							accepting: 'accepting',
						};
						post(map[phase] ?? 'provisioning');
					},
				});

				const ev: SessionEvent = {
					type: 'result',
					id: cmd.id,
					result: {
						recoveryId: result.recoveryId,
						dwalletId: result.dwalletId,
						encryptedUserShareId: result.importerEncryptedUserShareId,
						txDigest: result.txDigests.create,
						// Approver-only entries get `null` ids → drop them from the
						// emitted list (they have nothing to broadcast).
						provisioned: result.nonImporterEncryptedUserShareIds
							.filter((id): id is string => id !== null)
							.map((id) => ({ destEncryptedUserShareId: id })),
					},
				};
				ctx.postMessage(ev);
				return;
			}
			case 'proposeRecovery': {
				if (!ikaClient || !suiClient || !recoveryClient)
					throw new Error('session worker not initialized');

				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);

				const result = await proposeRecovery(proposalClient, {
					sweepMessages: cmd.args.sweepMessages,
					authSigner: bridgeAuthSigner(cmd.id, cmd.args.authIdentity),
					gasSigner: executor,
				});

				const ev: SessionEvent = {
					type: 'proposeResult',
					id: cmd.id,
					result: {
						proposalId: result.proposalId.toString(),
						digest: result.digest,
						intentHashHex: bytesToHex(result.intentHash),
					},
				};
				ctx.postMessage(ev);
				return;
			}
			case 'approveRecovery': {
				if (!ikaClient || !suiClient || !recoveryClient)
					throw new Error('session worker not initialized');

				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);

				const result = await approveRecovery(proposalClient, {
					proposalId: BigInt(cmd.args.proposalId),
					authSigner: bridgeAuthSigner(cmd.id, cmd.args.authIdentity),
					gasSigner: executor,
				});

				const ev: SessionEvent = {
					type: 'approveResult',
					id: cmd.id,
					result: { digest: result.digest },
				};
				ctx.postMessage(ev);
				return;
			}
			case 'executeRecovery': {
				if (!ikaClient || !suiClient || !recoveryClient)
					throw new Error('session worker not initialized');

				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);

				const importerKeys = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
					cmd.args.importerKeyBytes,
				);
				const encryptedUserShare = await ikaClient.getEncryptedUserSecretKeyShare(
					cmd.args.encryptedUserShareId,
				);
				const solanaConnection = new (await import('@solana/web3.js')).Connection(
					cmd.args.solanaRpcUrl,
					'confirmed',
				);

				const result = await executeRecovery(proposalClient, {
					proposalId: BigInt(cmd.args.proposalId),
					authSigner: bridgeAuthSigner(cmd.id, cmd.args.authIdentity),
					userShareEncryptionKeys: importerKeys,
					encryptedUserShare,
					solanaConnection,
					gasSigner: executor,
					ikaFeePerMessage: cmd.args.ikaFeePerMessage,
					suiFeePerMessage: cmd.args.suiFeePerMessage,
					onProgress: (phase, detail) => {
						const ev: SessionEvent = {
							type: 'executeProgress',
							id: cmd.id,
							phase,
							index: detail?.index,
							total: detail?.total,
						};
						ctx.postMessage(ev);
					},
				});

				const ev: SessionEvent = {
					type: 'executeResult',
					id: cmd.id,
					result: {
						digest: result.digest,
						signedTransactions: result.signedTransactions,
						signIds: result.signIds,
					},
				};
				ctx.postMessage(ev);
				return;
			}
			case 'proposeEnrollment': {
				if (!recoveryClient) throw new Error('session worker not initialized');
				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);
				const result = await proposeEnrollment(proposalClient, {
					newMember: cmd.args.newMember,
					newEncryptionKeyAddress: cmd.args.newEncryptionKeyAddress,
					authSigner: bridgeAuthSigner(cmd.id, cmd.args.authIdentity),
					gasSigner: executor,
				});
				const ev: SessionEvent = {
					type: 'proposeEnrollmentResult',
					id: cmd.id,
					result: {
						enrollmentId: result.enrollmentId.toString(),
						digest: result.digest,
					},
				};
				ctx.postMessage(ev);
				return;
			}
			case 'approveEnrollment': {
				if (!recoveryClient) throw new Error('session worker not initialized');
				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);
				const result = await approveEnrollment(proposalClient, {
					enrollmentId: BigInt(cmd.args.enrollmentId),
					authSigner: bridgeAuthSigner(cmd.id, cmd.args.authIdentity),
					gasSigner: executor,
				});
				const ev: SessionEvent = {
					type: 'approveEnrollmentResult',
					id: cmd.id,
					result: { digest: result.digest },
				};
				ctx.postMessage(ev);
				return;
			}
			case 'executeApproverEnrollment': {
				if (!recoveryClient) throw new Error('session worker not initialized');
				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);
				const result = await executeApproverOnlyEnrollment(proposalClient, {
					enrollmentId: BigInt(cmd.args.enrollmentId),
					gasSigner: executor,
				});
				const ev: SessionEvent = {
					type: 'executeApproverEnrollmentResult',
					id: cmd.id,
					result: { digest: result.digest },
				};
				ctx.postMessage(ev);
				return;
			}
			case 'registerDeviceEncryptionKey': {
				if (!recoveryClient) throw new Error('session worker not initialized');
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);
				const newDeviceKeys = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
					cmd.args.newDeviceKeyBytes,
				);
				const result = await registerDeviceEncryptionKey(recoveryClient, {
					userShareEncryptionKeys: newDeviceKeys,
					gasSigner: executor,
				});
				const ev: SessionEvent = {
					type: 'registerDeviceEncryptionKeyResult',
					id: cmd.id,
					result: { digest: result.digest },
				};
				ctx.postMessage(ev);
				return;
			}
			case 'proposeRosterChange': {
				if (!recoveryClient) throw new Error('session worker not initialized');
				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);
				const result = await proposeRosterChange(proposalClient, {
					membersToRemove: cmd.args.membersToRemove,
					newThreshold: cmd.args.newThreshold === null ? null : BigInt(cmd.args.newThreshold),
					authSigner: bridgeAuthSigner(cmd.id, cmd.args.authIdentity),
					gasSigner: executor,
				});
				const ev: SessionEvent = {
					type: 'proposeRosterChangeResult',
					id: cmd.id,
					result: {
						rosterChangeId: result.rosterChangeId.toString(),
						digest: result.digest,
					},
				};
				ctx.postMessage(ev);
				return;
			}
			case 'approveRosterChange': {
				if (!recoveryClient) throw new Error('session worker not initialized');
				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);
				const result = await approveRosterChange(proposalClient, {
					rosterChangeId: BigInt(cmd.args.rosterChangeId),
					authSigner: bridgeAuthSigner(cmd.id, cmd.args.authIdentity),
					gasSigner: executor,
				});
				const ev: SessionEvent = {
					type: 'approveRosterChangeResult',
					id: cmd.id,
					result: { digest: result.digest },
				};
				ctx.postMessage(ev);
				return;
			}
			case 'executeRosterChange': {
				if (!recoveryClient) throw new Error('session worker not initialized');
				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);
				const result = await executeRosterChange(proposalClient, {
					rosterChangeId: BigInt(cmd.args.rosterChangeId),
					gasSigner: executor,
				});
				const ev: SessionEvent = {
					type: 'executeRosterChangeResult',
					id: cmd.id,
					result: { digest: result.digest },
				};
				ctx.postMessage(ev);
				return;
			}
			case 'executeKeyHolderEnrollment': {
				if (!ikaClient || !recoveryClient) throw new Error('session worker not initialized');
				const proposalClient = makeProposalClient(cmd.args.recoveryId);
				const executor = makeMainThreadExecutor(cmd.args.walletAddress, cmd.id);

				let importerKeys: UserShareEncryptionKeys;
				try {
					importerKeys = UserShareEncryptionKeys.fromShareEncryptionKeysBytes(
						cmd.args.importerKeyBytes,
					);
				} catch (e) {
					throw new Error(
						`loading importer keys (${cmd.args.importerKeyBytes.byteLength}-byte ` +
							`payload from local cache): ${e instanceof Error ? e.message : String(e)}`,
					);
				}

				const sourceShare = await ikaClient
					.getEncryptedUserSecretKeyShare(cmd.args.encryptedUserShareId)
					.catch((e: unknown) => {
						throw new Error(
							`fetching source encrypted share ${cmd.args.encryptedUserShareId}: ` +
								(e instanceof Error ? e.message : String(e)),
						);
					});

				const result = await executeEnrollment(proposalClient, {
					enrollmentId: BigInt(cmd.args.enrollmentId),
					userShareEncryptionKeys: importerKeys,
					sourceEncryptedUserShare: sourceShare,
					newEncryptionKeyAddress: cmd.args.newEncryptionKeyAddress,
					gasSigner: executor,
					// Ika's `request_re_encrypt_user_share_for` charges a pricing-
					// table fee that's set on-chain. Pass enough that we don't bump
					// EInsufficientIKAPayment if the network raises pricing — the
					// SDK transfers the leftover coins back to the executor at the
					// end of the PTB, so overpaying is free.
					ikaFee: 2_000_000_000n,
					suiFee: 200_000_000n,
				}).catch((e: unknown) => {
					throw new Error(
						`executeEnrollment (decrypt+re-encrypt+submit): ` +
							(e instanceof Error ? e.message : String(e)),
					);
				});
				const ev: SessionEvent = {
					type: 'executeKeyHolderEnrollmentResult',
					id: cmd.id,
					result: {
						digest: result.digest,
						destEncryptedUserShareId: result.destEncryptedUserShareId,
					},
				};
				ctx.postMessage(ev);
				return;
			}
		}
	} catch (err) {
		const ev: SessionEvent = {
			type: 'error',
			id: cmd.id,
			error: err instanceof Error ? err.message : String(err),
		};
		ctx.postMessage(ev);
	}
});

void Transaction;
