import {
	Connection,
	PublicKey,
	TransactionMessage,
	VersionedTransaction,
	type AddressLookupTableAccount,
	type Signer,
} from '@solana/web3.js';

import {
	buildApproveRosterChangeIx,
	type ApproveRosterChangeParams,
} from '../ix/approve-roster-change';
import {
	buildExecuteRosterChangeIx,
	type ExecuteRosterChangeParams,
} from '../ix/execute-roster-change';
import {
	buildProposeRosterChangeIx,
	type ProposeRosterChangeParams,
} from '../ix/propose-roster-change';
import {
	buildStageRosterChangePayloadIx,
	type StageRosterChangePayloadParams,
} from '../ix/stage-roster-change';

export interface RosterChangeSendOptions {
	connection: Connection;
	payer: Signer;
	extraSigners?: Signer[];
	commitment?: 'processed' | 'confirmed' | 'finalized';
	skipPreflight?: boolean;
	/**
	 * ALT compression. The propose ix carries two 544-byte member buffers and
	 * exceeds the legacy tx cap on devnet/mainnet without compression.
	 */
	lookupTables?: AddressLookupTableAccount[];
}

async function sendOne(
	ix: import('@solana/web3.js').TransactionInstruction,
	opts: RosterChangeSendOptions,
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

export interface ProposeRosterChangeFlowParams extends Omit<
	ProposeRosterChangeParams,
	'payer' | 'rosterChangeIndex'
> {
	proposer: Signer;
	/** Defaults to the on-chain `Recovery.roster_change_count`. */
	rosterChangeIndex?: number;
	/** Buffered payload contents (additions/removals/threshold). */
	stage: Pick<
		StageRosterChangePayloadParams,
		'additions' | 'removals' | 'additionApproverOnlyBitmap' | 'newThreshold'
	>;
}

export async function proposeRosterChangeAndConfirm(
	send: RosterChangeSendOptions,
	params: ProposeRosterChangeFlowParams,
): Promise<{
	stageSignature: string;
	proposeSignature: string;
	rosterChange: PublicKey;
	staging: PublicKey;
	rosterChangeIndex: number;
}> {
	const rosterChangeIndex =
		params.rosterChangeIndex ??
		(await defaultIndex(send.connection, params.recovery, 'rosterChangeCount'));

	// Stage tx: bulky additions/removals + threshold buffered to a per-index PDA.
	const { ix: stageIx, staging } = buildStageRosterChangePayloadIx({
		recovery: params.recovery,
		recoveryId: params.recoveryId,
		rosterChangeIndex,
		payer: params.proposer.publicKey,
		additions: params.stage.additions,
		removals: params.stage.removals,
		additionApproverOnlyBitmap: params.stage.additionApproverOnlyBitmap,
		newThreshold: params.stage.newThreshold,
	});
	const stageSignature = await sendOne(stageIx, {
		...send,
		payer: params.proposer,
	});

	// Propose tx: small ix that only carries payload_hash + auth args; reads
	// the buffered payload from `staging`, closes it for rent refund.
	const { ix, rosterChange } = buildProposeRosterChangeIx({
		recovery: params.recovery,
		recoveryId: params.recoveryId,
		rosterChangeIndex,
		payer: params.proposer.publicKey,
		payloadHash: params.payloadHash,
		credential: params.credential,
	});
	const proposeSignature = await sendOne(ix, {
		...send,
		payer: params.proposer,
	});
	return {
		stageSignature,
		proposeSignature,
		rosterChange,
		staging,
		rosterChangeIndex,
	};
}

export interface ApproveRosterChangeFlowParams extends Omit<ApproveRosterChangeParams, 'payer'> {
	approver: Signer;
	feePayer?: Signer;
}

export async function approveRosterChangeAndConfirm(
	send: RosterChangeSendOptions,
	params: ApproveRosterChangeFlowParams,
): Promise<{ signature: string; approval: PublicKey }> {
	const feePayer = params.feePayer ?? params.approver;
	const { ix, approval } = buildApproveRosterChangeIx({
		recovery: params.recovery,
		rosterChange: params.rosterChange,
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

export interface ExecuteRosterChangeFlowParams extends Omit<ExecuteRosterChangeParams, 'payer'> {
	executor: Signer;
}

export async function executeRosterChangeAndConfirm(
	send: RosterChangeSendOptions,
	params: ExecuteRosterChangeFlowParams,
): Promise<{ signature: string }> {
	const ix = buildExecuteRosterChangeIx({
		recovery: params.recovery,
		rosterChange: params.rosterChange,
		payer: params.executor.publicKey,
	});
	const signature = await sendOne(ix, {
		...send,
		payer: params.executor,
	});
	return { signature };
}

async function defaultIndex(
	connection: Connection,
	recovery: PublicKey,
	field: 'rosterChangeCount' | 'enrollmentCount' | 'proposalCount',
): Promise<number> {
	const { readRecovery } = await import('./state');
	const account = await readRecovery(connection, recovery);
	if (!account) {
		throw new Error(`recovery PDA ${recovery.toBase58()} not found`);
	}
	return account[field];
}
