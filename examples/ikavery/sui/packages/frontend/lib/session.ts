'use client';

import {
	getGrpcFullnodeUrl,
	type CredentialInput,
	type NewMemberInput,
	type TransactionExecuteResult,
} from '@fesal-packages/ikavery-sui-sdk';
import type { ClientWithCoreApi } from '@mysten/sui/client';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { Transaction } from '@mysten/sui/transactions';

import type {
	ApproveEnrollmentResultDTO,
	ApproveRecoveryResultDTO,
	ApproveRosterChangeResultDTO,
	AuthIdentity,
	ExecuteApproverEnrollmentResultDTO,
	ExecuteKeyHolderEnrollmentResultDTO,
	ExecuteRecoveryResultDTO,
	ExecuteRosterChangeResultDTO,
	ImportKeyResult,
	ProposeEnrollmentResultDTO,
	ProposeRecoveryResultDTO,
	ProposeRosterChangeResultDTO,
	RegisterDeviceEncryptionKeyResultDTO,
	SessionConfig,
	SessionEvent,
} from '@/workers/session.worker';

import { env } from './env';

export type ImportKeyPhase = 'preparing' | 'verifying' | 'accepting' | 'provisioning';

export type ExecutePhase =
	| 'reading-proposal'
	| 'fetching-blockhash'
	| 'decrypting-share'
	| 'waiting-for-presigns'
	| 'building-signatures'
	| 'auth-ceremony'
	| 'submitting-execute'
	| 'waiting-for-sign-sessions'
	| 'assembling';

export interface ExecuteProgressDetail {
	phase: ExecutePhase;
	/** Set only for `waiting-for-sign-sessions` to drive a "1/n" counter. */
	index?: number;
	total?: number;
}

/** Sign callback the main thread provides for sponsor-wallet tx submission. */
export type WalletSignAndExecute = (transaction: Transaction) => Promise<TransactionExecuteResult>;

/**
 * Caller-supplied bridge that resolves a worker `credentialRequest` into a
 * `CredentialInput`. The page implementation routes this through WebAuthn or
 * the wallet's `signPersonalMessage` based on the identity.
 */
export type ResolveCredential = (
	challenge: Uint8Array,
	identity: AuthIdentity,
) => Promise<CredentialInput>;

export interface SessionRunProposeArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	resolveCredential: ResolveCredential;
	recoveryId: string;
	sweepMessages: Uint8Array[];
	authIdentity: AuthIdentity;
}

export interface SessionRunApproveArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	resolveCredential: ResolveCredential;
	recoveryId: string;
	proposalId: string;
	authIdentity: AuthIdentity;
}

export interface SessionRunProposeEnrollmentArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	resolveCredential: ResolveCredential;
	recoveryId: string;
	newMember: NewMemberInput;
	newEncryptionKeyAddress: string;
	authIdentity: AuthIdentity;
}

export interface SessionRunApproveEnrollmentArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	resolveCredential: ResolveCredential;
	recoveryId: string;
	enrollmentId: string;
	authIdentity: AuthIdentity;
}

export interface SessionRunExecuteApproverEnrollmentArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	recoveryId: string;
	enrollmentId: string;
}

export interface SessionRunExecuteKeyHolderEnrollmentArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	recoveryId: string;
	enrollmentId: string;
	importerKeyBytes: Uint8Array;
	encryptedUserShareId: string;
	newEncryptionKeyAddress: string;
}

export interface SessionRunRegisterDeviceEncryptionKeyArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	newDeviceKeyBytes: Uint8Array;
}

export interface SessionRunProposeRosterChangeArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	resolveCredential: ResolveCredential;
	recoveryId: string;
	/** Canonical member ids to remove (`[scheme, ...pubkey/addr]` shape). */
	membersToRemove: Uint8Array[];
	/** `null` to keep the current threshold. */
	newThreshold: bigint | null;
	authIdentity: AuthIdentity;
}

export interface SessionRunApproveRosterChangeArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	resolveCredential: ResolveCredential;
	recoveryId: string;
	rosterChangeId: string;
	authIdentity: AuthIdentity;
}

export interface SessionRunExecuteRosterChangeArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	recoveryId: string;
	rosterChangeId: string;
}

export interface SessionRunExecuteArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	resolveCredential: ResolveCredential;
	recoveryId: string;
	proposalId: string;
	importerKeyBytes: Uint8Array;
	encryptedUserShareId: string;
	solanaRpcUrl: string;
	authIdentity: AuthIdentity;
	ikaFeePerMessage?: bigint;
	suiFeePerMessage?: bigint;
	onProgress?: (detail: ExecuteProgressDetail) => void;
}

/**
 * Per-non-importer-member entry, parallel to `initialMembers[1..]`. Approver-
 * only entries (zkLogin / MultiSig / Passkey-as-sender) carry no encryption
 * identity — those members can vote but can't execute.
 */
export type AdditionalMember =
	{ kind: 'key-holder'; keyBytes: Uint8Array } | { kind: 'approver-only' };

export interface SessionRunImportArgs {
	walletAddress: string;
	signAndExecute: WalletSignAndExecute;
	importerKeyBytes: Uint8Array;
	solanaSecretKey: Uint8Array;
	initialMembers: NewMemberInput[];
	threshold: number;
	/** Parallel to `initialMembers[1..]`. */
	additionalMembers?: AdditionalMember[];
	verificationIkaFee?: bigint;
	verificationSuiFee?: bigint;
	onProgress?: (phase: ImportKeyPhase) => void;
}

interface PendingJob {
	resolve: (r: unknown) => void;
	reject: (e: Error) => void;
	onProgress?: (phase: ImportKeyPhase) => void;
	onExecuteProgress?: (detail: ExecuteProgressDetail) => void;
	signAndExecute?: WalletSignAndExecute;
	resolveCredential?: ResolveCredential;
}

export class Session {
	private worker: Worker;
	private nextId = 1;
	private pending = new Map<number, PendingJob>();
	readonly ready: Promise<void>;
	readonly suiClient: ClientWithCoreApi;

	private constructor(config: SessionConfig) {
		const url = config.rpcUrl || getGrpcFullnodeUrl(config.network);
		this.suiClient = new SuiGrpcClient({ baseUrl: url, network: config.network });

		this.worker = new Worker(new URL('../workers/session.worker.ts', import.meta.url), {
			type: 'module',
			name: 'ika-session',
		});
		this.worker.addEventListener('message', (e: MessageEvent<SessionEvent>) => {
			const ev = e.data;
			if (ev.type === 'signRequest') {
				void this.handleSignRequest(ev.id, ev.jobId, ev.txJson);
				return;
			}
			if (ev.type === 'credentialRequest') {
				void this.handleCredentialRequest(ev.id, ev.jobId, ev.challenge, ev.identity);
				return;
			}
			const job = this.pending.get(ev.id);
			if (!job) return;
			switch (ev.type) {
				case 'progress':
					job.onProgress?.(ev.phase);
					break;
				case 'executeProgress':
					job.onExecuteProgress?.({
						phase: ev.phase,
						index: ev.index,
						total: ev.total,
					});
					break;
				case 'ready':
					this.pending.delete(ev.id);
					job.resolve(undefined);
					break;
				case 'result':
					this.pending.delete(ev.id);
					job.resolve(ev.result);
					break;
				case 'proposeResult':
				case 'approveResult':
				case 'executeResult':
				case 'proposeEnrollmentResult':
				case 'approveEnrollmentResult':
				case 'executeApproverEnrollmentResult':
				case 'executeKeyHolderEnrollmentResult':
				case 'registerDeviceEncryptionKeyResult':
				case 'proposeRosterChangeResult':
				case 'approveRosterChangeResult':
				case 'executeRosterChangeResult':
					this.pending.delete(ev.id);
					job.resolve(ev.result);
					break;
				case 'error':
					this.pending.delete(ev.id);
					job.reject(new Error(ev.error));
					break;
			}
		});
		this.worker.addEventListener('error', (e) => {
			const err = new Error(e.message || 'session worker error');
			for (const [id, job] of this.pending) {
				this.pending.delete(id);
				job.reject(err);
			}
		});

		const id = this.nextId++;
		this.ready = new Promise<void>((resolve, reject) => {
			this.pending.set(id, {
				resolve: () => resolve(),
				reject,
			});
		});
		this.worker.postMessage({ type: 'init', id, config });
	}

	private async handleSignRequest(signId: number, jobId: number, txJson: string): Promise<void> {
		const job = this.pending.get(jobId);
		try {
			if (!job?.signAndExecute) {
				throw new Error('no wallet signer attached for this job');
			}
			const transaction = Transaction.from(txJson);
			const result = await job.signAndExecute(transaction);
			this.worker.postMessage({
				type: 'signResponse',
				id: signId,
				ok: true,
				result,
			});
		} catch (err) {
			this.worker.postMessage({
				type: 'signResponse',
				id: signId,
				ok: false,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}

	private async handleCredentialRequest(
		credId: number,
		jobId: number,
		challenge: Uint8Array,
		identity: AuthIdentity,
	): Promise<void> {
		const job = this.pending.get(jobId);
		try {
			if (!job?.resolveCredential) {
				throw new Error('no credential resolver attached for this job');
			}
			const credential = await job.resolveCredential(challenge, identity);
			this.worker.postMessage({
				type: 'credentialResponse',
				id: credId,
				ok: true,
				credential,
			});
		} catch (err) {
			this.worker.postMessage({
				type: 'credentialResponse',
				id: credId,
				ok: false,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}

	private static singleton: Session | null = null;
	static get(): Session {
		if (!Session.singleton) {
			Session.singleton = new Session({
				network: env.network,
				rpcUrl: env.suiRpcUrl ?? '',
				recoveryPackageId: env.recoveryPackageId,
				recoveryRegistryId: env.recoveryRegistryId,
				rpId: env.rpId,
			});
		}
		return Session.singleton;
	}

	runImportSolanaKey(args: SessionRunImportArgs): Promise<ImportKeyResult> {
		const id = this.nextId++;
		return new Promise<ImportKeyResult>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ImportKeyResult),
				reject,
				onProgress: args.onProgress,
				signAndExecute: args.signAndExecute,
			});
			this.worker.postMessage({
				type: 'importSolanaKey',
				id,
				args: {
					walletAddress: args.walletAddress,
					importerKeyBytes: args.importerKeyBytes,
					solanaSecretKey: args.solanaSecretKey,
					initialMembers: args.initialMembers,
					threshold: args.threshold,
					additionalMembers: args.additionalMembers ?? [],
					verificationIkaFee: args.verificationIkaFee ?? 500_000_000n,
					verificationSuiFee: args.verificationSuiFee ?? 50_000_000n,
				},
			});
		});
	}

	runProposeRecovery(args: SessionRunProposeArgs): Promise<ProposeRecoveryResultDTO> {
		const id = this.nextId++;
		return new Promise<ProposeRecoveryResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ProposeRecoveryResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
				resolveCredential: args.resolveCredential,
			});
			this.worker.postMessage({
				type: 'proposeRecovery',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					sweepMessages: args.sweepMessages,
					authIdentity: args.authIdentity,
				},
			});
		});
	}

	runApproveRecovery(args: SessionRunApproveArgs): Promise<ApproveRecoveryResultDTO> {
		const id = this.nextId++;
		return new Promise<ApproveRecoveryResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ApproveRecoveryResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
				resolveCredential: args.resolveCredential,
			});
			this.worker.postMessage({
				type: 'approveRecovery',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					proposalId: args.proposalId,
					authIdentity: args.authIdentity,
				},
			});
		});
	}

	runProposeEnrollment(args: SessionRunProposeEnrollmentArgs): Promise<ProposeEnrollmentResultDTO> {
		const id = this.nextId++;
		return new Promise<ProposeEnrollmentResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ProposeEnrollmentResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
				resolveCredential: args.resolveCredential,
			});
			this.worker.postMessage({
				type: 'proposeEnrollment',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					newMember: args.newMember,
					newEncryptionKeyAddress: args.newEncryptionKeyAddress,
					authIdentity: args.authIdentity,
				},
			});
		});
	}

	runApproveEnrollment(args: SessionRunApproveEnrollmentArgs): Promise<ApproveEnrollmentResultDTO> {
		const id = this.nextId++;
		return new Promise<ApproveEnrollmentResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ApproveEnrollmentResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
				resolveCredential: args.resolveCredential,
			});
			this.worker.postMessage({
				type: 'approveEnrollment',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					enrollmentId: args.enrollmentId,
					authIdentity: args.authIdentity,
				},
			});
		});
	}

	runExecuteApproverEnrollment(
		args: SessionRunExecuteApproverEnrollmentArgs,
	): Promise<ExecuteApproverEnrollmentResultDTO> {
		const id = this.nextId++;
		return new Promise<ExecuteApproverEnrollmentResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ExecuteApproverEnrollmentResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
			});
			this.worker.postMessage({
				type: 'executeApproverEnrollment',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					enrollmentId: args.enrollmentId,
				},
			});
		});
	}

	runRegisterDeviceEncryptionKey(
		args: SessionRunRegisterDeviceEncryptionKeyArgs,
	): Promise<RegisterDeviceEncryptionKeyResultDTO> {
		const id = this.nextId++;
		return new Promise<RegisterDeviceEncryptionKeyResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as RegisterDeviceEncryptionKeyResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
			});
			this.worker.postMessage({
				type: 'registerDeviceEncryptionKey',
				id,
				args: {
					walletAddress: args.walletAddress,
					newDeviceKeyBytes: args.newDeviceKeyBytes,
				},
			});
		});
	}

	runExecuteKeyHolderEnrollment(
		args: SessionRunExecuteKeyHolderEnrollmentArgs,
	): Promise<ExecuteKeyHolderEnrollmentResultDTO> {
		const id = this.nextId++;
		return new Promise<ExecuteKeyHolderEnrollmentResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ExecuteKeyHolderEnrollmentResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
			});
			this.worker.postMessage({
				type: 'executeKeyHolderEnrollment',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					enrollmentId: args.enrollmentId,
					importerKeyBytes: args.importerKeyBytes,
					encryptedUserShareId: args.encryptedUserShareId,
					newEncryptionKeyAddress: args.newEncryptionKeyAddress,
				},
			});
		});
	}

	runProposeRosterChange(
		args: SessionRunProposeRosterChangeArgs,
	): Promise<ProposeRosterChangeResultDTO> {
		const id = this.nextId++;
		return new Promise<ProposeRosterChangeResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ProposeRosterChangeResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
				resolveCredential: args.resolveCredential,
			});
			this.worker.postMessage({
				type: 'proposeRosterChange',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					membersToRemove: args.membersToRemove,
					// bigint isn't structured-clonable across the worker boundary in
					// every browser engine — serialize as a decimal string.
					newThreshold: args.newThreshold === null ? null : args.newThreshold.toString(),
					authIdentity: args.authIdentity,
				},
			});
		});
	}

	runApproveRosterChange(
		args: SessionRunApproveRosterChangeArgs,
	): Promise<ApproveRosterChangeResultDTO> {
		const id = this.nextId++;
		return new Promise<ApproveRosterChangeResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ApproveRosterChangeResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
				resolveCredential: args.resolveCredential,
			});
			this.worker.postMessage({
				type: 'approveRosterChange',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					rosterChangeId: args.rosterChangeId,
					authIdentity: args.authIdentity,
				},
			});
		});
	}

	runExecuteRosterChange(
		args: SessionRunExecuteRosterChangeArgs,
	): Promise<ExecuteRosterChangeResultDTO> {
		const id = this.nextId++;
		return new Promise<ExecuteRosterChangeResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ExecuteRosterChangeResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
			});
			this.worker.postMessage({
				type: 'executeRosterChange',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					rosterChangeId: args.rosterChangeId,
				},
			});
		});
	}

	runExecuteRecovery(args: SessionRunExecuteArgs): Promise<ExecuteRecoveryResultDTO> {
		const id = this.nextId++;
		return new Promise<ExecuteRecoveryResultDTO>((resolve, reject) => {
			this.pending.set(id, {
				resolve: (r) => resolve(r as ExecuteRecoveryResultDTO),
				reject,
				signAndExecute: args.signAndExecute,
				resolveCredential: args.resolveCredential,
				onExecuteProgress: args.onProgress,
			});
			this.worker.postMessage({
				type: 'executeRecovery',
				id,
				args: {
					walletAddress: args.walletAddress,
					recoveryId: args.recoveryId,
					proposalId: args.proposalId,
					importerKeyBytes: args.importerKeyBytes,
					encryptedUserShareId: args.encryptedUserShareId,
					solanaRpcUrl: args.solanaRpcUrl,
					authIdentity: args.authIdentity,
					ikaFeePerMessage: args.ikaFeePerMessage ?? 500_000_000n,
					suiFeePerMessage: args.suiFeePerMessage ?? 20_000_000n,
				},
			});
		});
	}
}
