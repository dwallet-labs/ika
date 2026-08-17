import { bcs } from '@mysten/sui/bcs';
import type { Keypair } from '@mysten/sui/cryptography';
import { Transaction } from '@mysten/sui/transactions';

import type { RecoveryClient } from '../client';
import {
	buildRosterChangeApproveChallenge,
	buildRosterChangeProposeChallenge,
} from '../crypto/challenges';
import { executorFromKeypair, type TransactionExecutor } from '../executor';
import * as moveRecovery from '../generated/recovery/recovery';
import { buildCredential, type AuthSigner } from '../move/credential';
import { readRecoveryState } from './state';

// ===== proposeRosterChange =====

export interface ProposeRosterChangeParams {
	/**
	 * Canonical member ids to remove. Each entry is `[scheme, ...pubkey/addr]`
	 * — the same shape `RecoveryState.members` returns. Must all be currently in
	 * the set (Move aborts otherwise).
	 */
	membersToRemove: Uint8Array[];
	/**
	 * `null` to keep the current threshold; pass a `bigint` to also change it.
	 * Must satisfy `MIN_THRESHOLD ≤ t ≤ (members.length - membersToRemove.length)`.
	 */
	newThreshold: bigint | null;
	/** Caller's auth — must be an existing member. */
	authSigner: AuthSigner;
	gasSigner: Keypair | TransactionExecutor;
}

export interface ProposeRosterChangeResult {
	rosterChangeId: bigint;
	digest: string;
}

export async function proposeRosterChange(
	client: RecoveryClient,
	params: ProposeRosterChangeParams,
): Promise<ProposeRosterChangeResult> {
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);
	const state = await readRecoveryState(client);

	const challenge = buildRosterChangeProposeChallenge(
		client.ref.recoveryId,
		params.membersToRemove,
		params.newThreshold,
		state.nonce,
	);
	const credentialInput = await params.authSigner.sign(challenge);

	const tx = new Transaction();
	const credArg = buildCredential(tx, client.ref.packageId, credentialInput);

	// membersToRemove serialized as vector<vector<u8>>; the codegen wants
	// Array<Array<number>> but bigints/uint8arrays work via .map.
	const removalsArg = params.membersToRemove.map((id) => Array.from(id));

	// Option<u64>: null → none, bigint → some.
	const thresholdArg = params.newThreshold === null ? null : params.newThreshold;

	client.move.proposeRosterChange({
		self: client.ref.recoveryId,
		membersToRemove: removalsArg,
		newThreshold: thresholdArg,
		cred: credArg,
	})(tx);

	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(
			`proposeRosterChange: failed: ${JSON.stringify(result.FailedTransaction.status)}`,
		);
	}
	return {
		rosterChangeId: state.nextRosterChangeId,
		digest: result.Transaction.digest,
	};
}

// ===== approveRosterChange =====

export interface ApproveRosterChangeParams {
	rosterChangeId: bigint;
	authSigner: AuthSigner;
	gasSigner: Keypair | TransactionExecutor;
}

export async function approveRosterChange(
	client: RecoveryClient,
	params: ApproveRosterChangeParams,
): Promise<{ digest: string }> {
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);

	const challenge = buildRosterChangeApproveChallenge(client.ref.recoveryId, params.rosterChangeId);
	const credentialInput = await params.authSigner.sign(challenge);

	const tx = new Transaction();
	const credArg = buildCredential(tx, client.ref.packageId, credentialInput);
	client.move.approveRosterChange({
		self: client.ref.recoveryId,
		rosterChangeId: params.rosterChangeId,
		cred: credArg,
	})(tx);

	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(
			`approveRosterChange: failed: ${JSON.stringify(result.FailedTransaction.status)}`,
		);
	}
	return { digest: result.Transaction.digest };
}

// ===== executeRosterChange =====

export interface ExecuteRosterChangeParams {
	rosterChangeId: bigint;
	gasSigner: Keypair | TransactionExecutor;
}

/**
 * Apply an approved roster change. Pure shared-object mutation — no Ika ops
 * and no IKA fee. Auth is the threshold check inside Move; no extra signature
 * is needed at execute time.
 */
export async function executeRosterChange(
	client: RecoveryClient,
	params: ExecuteRosterChangeParams,
): Promise<{ digest: string }> {
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);
	const tx = new Transaction();
	client.move.executeRosterChange({
		self: client.ref.recoveryId,
		rosterChangeId: params.rosterChangeId,
	})(tx);

	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(
			`executeRosterChange: failed: ${JSON.stringify(result.FailedTransaction.status)}`,
		);
	}
	return { digest: result.Transaction.digest };
}

// ===== readRosterChange / listRosterChangeSnapshots =====

export interface RosterChangeSnapshot {
	rosterChangeId: bigint;
	/** Canonical member-ids to remove. Each entry is `[scheme, ...pubkey/addr]`. */
	membersToRemove: Uint8Array[];
	/** `null` if the proposal keeps the current threshold. */
	newThreshold: bigint | null;
	approvals: bigint;
	voters: Uint8Array[];
	executed: boolean;
}

export async function readRosterChange(
	client: RecoveryClient,
	rosterChangeId: bigint,
): Promise<RosterChangeSnapshot> {
	const state = await readRecoveryState(client);
	const { dynamicField } = await client.suiClient.core.getDynamicField({
		parentId: state.rosterChangesTableId,
		name: { type: 'u64', bcs: bcs.u64().serialize(rosterChangeId).toBytes() },
	});
	const raw = moveRecovery.RosterChangeProposal.parse(dynamicField.value.bcs);
	// bcs.option(bcs.u64()) parses to a `string | null` (u64 stringified, or
	// null for `None`).
	const newThreshold: bigint | null = raw.new_threshold === null ? null : BigInt(raw.new_threshold);

	return {
		rosterChangeId,
		membersToRemove: raw.members_to_remove.map((b) => Uint8Array.from(b)),
		newThreshold,
		approvals: BigInt(raw.approvals),
		voters: raw.voters.contents.map((b) => Uint8Array.from(b)),
		executed: raw.executed,
	};
}

/** Best-effort scan of `[0..nextRosterChangeId)`. */
export async function listRosterChangeSnapshots(
	client: RecoveryClient,
): Promise<RosterChangeSnapshot[]> {
	const state = await readRecoveryState(client);
	const out: RosterChangeSnapshot[] = [];
	for (let i = 0n; i < state.nextRosterChangeId; i++) {
		try {
			out.push(await readRosterChange(client, i));
		} catch {
			/* missing dynamic field — tolerate */
		}
	}
	return out;
}
