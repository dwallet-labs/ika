import { Connection, PublicKey } from '@solana/web3.js';

import { decodeApproval, type ApprovalAccount } from '../codec/approvals';
import { decodeEnrollmentProposal, type EnrollmentProposalAccount } from '../codec/enrollment';
import { decodeProposal, type ProposalAccount } from '../codec/proposal';
import { decodeRecovery, type RecoveryAccount } from '../codec/recovery';
import {
	decodeRosterChangeProposal,
	type RosterChangeProposalAccount,
} from '../codec/roster-change';
import {
	approvalPda,
	enrollmentPda,
	memberIdHash,
	proposalPda,
	recoveryPda,
	rosterChangePda,
} from '../pda';

/**
 * Standalone read helpers around the existing decoders. The SDK doesn't keep
 * a stateful client object — `Connection` is the source of truth and every
 * flow takes it explicitly so callers can pin commitment / RPC per call.
 */

export interface ReadOptions {
	/** Defaults to the connection's commitment. */
	commitment?: 'processed' | 'confirmed' | 'finalized';
}

async function fetch(
	connection: Connection,
	account: PublicKey,
	opts?: ReadOptions,
): Promise<Uint8Array | null> {
	const info = await connection.getAccountInfo(account, opts?.commitment);
	if (!info) return null;
	return new Uint8Array(info.data);
}

export async function readRecovery(
	connection: Connection,
	recovery: PublicKey,
	opts?: ReadOptions,
): Promise<RecoveryAccount | null> {
	const data = await fetch(connection, recovery, opts);
	return data ? decodeRecovery(data) : null;
}

export async function readRecoveryById(
	connection: Connection,
	recoveryId: PublicKey,
	opts?: ReadOptions,
): Promise<{ pda: PublicKey; account: RecoveryAccount } | null> {
	const pda = recoveryPda(recoveryId);
	const account = await readRecovery(connection, pda, opts);
	return account ? { pda, account } : null;
}

export async function readProposal(
	connection: Connection,
	proposal: PublicKey,
	opts?: ReadOptions,
): Promise<ProposalAccount | null> {
	const data = await fetch(connection, proposal, opts);
	return data ? decodeProposal(data) : null;
}

export async function readProposalByIndex(
	connection: Connection,
	recovery: PublicKey,
	index: number,
	opts?: ReadOptions,
): Promise<{ pda: PublicKey; account: ProposalAccount } | null> {
	const pda = proposalPda(recovery, index);
	const account = await readProposal(connection, pda, opts);
	return account ? { pda, account } : null;
}

export async function readRosterChange(
	connection: Connection,
	rosterChange: PublicKey,
	opts?: ReadOptions,
): Promise<RosterChangeProposalAccount | null> {
	const data = await fetch(connection, rosterChange, opts);
	return data ? decodeRosterChangeProposal(data) : null;
}

export async function readRosterChangeByIndex(
	connection: Connection,
	recovery: PublicKey,
	index: number,
	opts?: ReadOptions,
): Promise<{ pda: PublicKey; account: RosterChangeProposalAccount } | null> {
	const pda = rosterChangePda(recovery, index);
	const account = await readRosterChange(connection, pda, opts);
	return account ? { pda, account } : null;
}

export async function readEnrollment(
	connection: Connection,
	enrollment: PublicKey,
	opts?: ReadOptions,
): Promise<EnrollmentProposalAccount | null> {
	const data = await fetch(connection, enrollment, opts);
	return data ? decodeEnrollmentProposal(data) : null;
}

export async function readEnrollmentByIndex(
	connection: Connection,
	recovery: PublicKey,
	index: number,
	opts?: ReadOptions,
): Promise<{ pda: PublicKey; account: EnrollmentProposalAccount } | null> {
	const pda = enrollmentPda(recovery, index);
	const account = await readEnrollment(connection, pda, opts);
	return account ? { pda, account } : null;
}

export async function readApproval(
	connection: Connection,
	approval: PublicKey,
	opts?: ReadOptions,
): Promise<ApprovalAccount | null> {
	const data = await fetch(connection, approval, opts);
	return data ? decodeApproval(data) : null;
}

/**
 * Convenience: read the Approval row for a given (proposal, memberSlot)
 * pair. Returns null when the member hasn't voted yet — useful for
 * deduping / showing "already approved" UI without re-running the ix.
 */
export async function readApprovalForMember(
	connection: Connection,
	proposal: PublicKey,
	memberSlot: Uint8Array,
	opts?: ReadOptions,
): Promise<{ pda: PublicKey; account: ApprovalAccount } | null> {
	const memberHash = memberIdHash(memberSlot);
	const pda = approvalPda(proposal, memberHash);
	const account = await readApproval(connection, pda, opts);
	return account ? { pda, account } : null;
}
