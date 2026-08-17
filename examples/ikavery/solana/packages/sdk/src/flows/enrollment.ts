import {
	Connection,
	PublicKey,
	TransactionMessage,
	VersionedTransaction,
	type AddressLookupTableAccount,
	type Signer,
} from '@solana/web3.js';

import { buildApproveEnrollmentIx, type ApproveEnrollmentParams } from '../ix/approve-enrollment';
import { buildExecuteEnrollmentIx, type ExecuteEnrollmentParams } from '../ix/execute-enrollment';
import { buildProposeEnrollmentIx, type ProposeEnrollmentParams } from '../ix/propose-enrollment';

export interface EnrollmentSendOptions {
	connection: Connection;
	payer: Signer;
	extraSigners?: Signer[];
	commitment?: 'processed' | 'confirmed' | 'finalized';
	skipPreflight?: boolean;
	lookupTables?: AddressLookupTableAccount[];
}

async function sendOne(
	ix: import('@solana/web3.js').TransactionInstruction,
	opts: EnrollmentSendOptions,
): Promise<string> {
	const commitment = opts.commitment ?? 'confirmed';
	const { blockhash, lastValidBlockHeight } = await opts.connection.getLatestBlockhash(commitment);
	const message = new TransactionMessage({
		payerKey: opts.payer.publicKey,
		recentBlockhash: blockhash,
		instructions: [ix],
	}).compileToV0Message(opts.lookupTables);
	const tx = new VersionedTransaction(message);
	tx.sign([opts.payer, ...(opts.extraSigners ?? [])]);
	const sig = await opts.connection.sendRawTransaction(tx.serialize(), {
		skipPreflight: opts.skipPreflight ?? false,
		preflightCommitment: commitment,
	});
	await opts.connection.confirmTransaction(
		{ signature: sig, blockhash, lastValidBlockHeight },
		commitment,
	);
	return sig;
}

export interface ProposeEnrollmentFlowParams extends Omit<
	ProposeEnrollmentParams,
	'payer' | 'enrollmentIndex'
> {
	proposer: Signer;
	/** Defaults to the on-chain `Recovery.enrollment_count`. */
	enrollmentIndex?: number;
}

export async function proposeEnrollmentAndConfirm(
	send: EnrollmentSendOptions,
	params: ProposeEnrollmentFlowParams,
): Promise<{
	signature: string;
	enrollment: PublicKey;
	enrollmentIndex: number;
}> {
	const enrollmentIndex =
		params.enrollmentIndex ?? (await defaultIndex(send.connection, params.recovery));
	const { ix, enrollment } = buildProposeEnrollmentIx({
		recovery: params.recovery,
		recoveryId: params.recoveryId,
		enrollmentIndex,
		payer: params.proposer.publicKey,
		newMember: params.newMember,
		newEncryptionKeyAddress: params.newEncryptionKeyAddress,
		additionApproverOnly: params.additionApproverOnly,
		credential: params.credential,
	});
	const signature = await sendOne(ix, {
		...send,
		payer: params.proposer,
	});
	return { signature, enrollment, enrollmentIndex };
}

export interface ApproveEnrollmentFlowParams extends Omit<ApproveEnrollmentParams, 'payer'> {
	approver: Signer;
	feePayer?: Signer;
}

export async function approveEnrollmentAndConfirm(
	send: EnrollmentSendOptions,
	params: ApproveEnrollmentFlowParams,
): Promise<{ signature: string; approval: PublicKey }> {
	const feePayer = params.feePayer ?? params.approver;
	const { ix, approval } = buildApproveEnrollmentIx({
		recovery: params.recovery,
		enrollment: params.enrollment,
		payer: feePayer.publicKey,
		memberSlot: params.memberSlot,
		credential: params.credential,
	});
	const extras = feePayer === params.approver ? [] : [params.approver];
	const signature = await sendOne(ix, {
		...send,
		payer: feePayer,
		extraSigners: [...extras, ...(send.extraSigners ?? [])],
	});
	return { signature, approval };
}

export interface ExecuteEnrollmentFlowParams extends Omit<ExecuteEnrollmentParams, 'payer'> {
	executor: Signer;
}

export async function executeEnrollmentAndConfirm(
	send: EnrollmentSendOptions,
	params: ExecuteEnrollmentFlowParams,
): Promise<{ signature: string }> {
	const ix = buildExecuteEnrollmentIx({
		recovery: params.recovery,
		enrollment: params.enrollment,
		payer: params.executor.publicKey,
	});
	const signature = await sendOne(ix, {
		...send,
		payer: params.executor,
	});
	return { signature };
}

async function defaultIndex(connection: Connection, recovery: PublicKey): Promise<number> {
	const { readRecovery } = await import('./state');
	const account = await readRecovery(connection, recovery);
	if (!account) {
		throw new Error(`recovery PDA ${recovery.toBase58()} not found`);
	}
	return account.enrollmentCount;
}
