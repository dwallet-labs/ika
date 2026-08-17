import {
	Connection,
	Keypair,
	PublicKey,
	TransactionMessage,
	VersionedTransaction,
	type AddressLookupTableAccount,
	type Signer,
	type TransactionInstruction,
} from '@solana/web3.js';

import { buildApproveIx, type ApproveParams } from '../ix/approve';
import { buildCreateRecoveryIx, type CreateRecoveryParams } from '../ix/create-recovery';
import { buildExecuteIx, type ExecuteParams } from '../ix/execute';
import { buildProposeIx, type ProposeParams } from '../ix/propose';
import { proposalPda } from '../pda';

/**
 * The minimum surface a flow helper needs to send a tx. Mirrors web3.js's
 * `confirmTransaction` semantics — accept any commitment string the RPC
 * understands.
 */
export interface SendOptions {
	connection: Connection;
	/** Pays fees + rent. Always required, even when the auth identity is decoupled. */
	payer: Signer;
	/** Extra signers beyond the fee payer (e.g. the `recoveryId` keypair on `create`). */
	extraSigners?: Signer[];
	/** Defaults to "confirmed". */
	commitment?: 'processed' | 'confirmed' | 'finalized';
	/** Skip preflight simulation — useful when the RPC is finicky. */
	skipPreflight?: boolean;
	/**
	 * Address-lookup tables to compress the v0 message. Required for `propose`
	 * on devnet/mainnet — the per-instruction wire is 47 bytes over the
	 * 1232-byte single-tx cap without ALT compression.
	 */
	lookupTables?: AddressLookupTableAccount[];
}

async function sendOne(ix: TransactionInstruction, opts: SendOptions): Promise<string> {
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

export interface CreateRecoveryFlowParams extends Omit<
	CreateRecoveryParams,
	'creator' | 'recoveryId'
> {
	/** The creator's keypair — pays for the new Recovery PDA + signs the tx. */
	creator: Signer;
	/**
	 * The recovery-id keypair. A throwaway nonce; only its address is stored
	 * on-chain (as the Recovery PDA seed). The signer is required because the
	 * runtime needs it to assert the address didn't pre-exist.
	 */
	recoveryId?: Signer;
}

/**
 * Build, sign, and confirm a `create_recovery` tx. Returns the new Recovery
 * PDA + the recoveryId keypair (auto-generated if not provided).
 */
export async function createRecoveryAndConfirm(
	send: SendOptions,
	params: CreateRecoveryFlowParams,
): Promise<{ signature: string; recovery: PublicKey; recoveryId: Keypair }> {
	const recoveryIdSigner = (params.recoveryId as Keypair) ?? Keypair.generate();
	const { ix, recovery } = buildCreateRecoveryIx({
		creator: params.creator.publicKey,
		recoveryId: recoveryIdSigner.publicKey,
		dwallet: params.dwallet,
		dwalletCurve: params.dwalletCurve,
		threshold: params.threshold,
		members: params.members,
		approverOnlyBitmap: params.approverOnlyBitmap,
	});
	const signature = await sendOne(ix, {
		...send,
		payer: params.creator,
		extraSigners: [recoveryIdSigner, ...(send.extraSigners ?? [])],
	});
	return { signature, recovery, recoveryId: recoveryIdSigner };
}

export interface ProposeFlowParams extends Omit<ProposeParams, 'proposer' | 'proposalIndex'> {
	/** Auth identity authorising the propose. The flow defaults `payer` to this. */
	proposer: Signer;
	/**
	 * Optional override. When omitted, the helper reads `Recovery.proposal_count`
	 * to derive the expected index — saves a hand-roll for the common case.
	 */
	proposalIndex?: number;
}

/**
 * Build, sign, and confirm a `propose` tx. Returns the proposal PDA and the
 * resolved index.
 */
export async function proposeAndConfirm(
	send: SendOptions,
	params: ProposeFlowParams,
): Promise<{ signature: string; proposal: PublicKey; proposalIndex: number }> {
	const proposalIndex =
		params.proposalIndex ?? (await defaultProposalIndex(send.connection, params.recovery));
	const { ix, proposal } = buildProposeIx({
		recovery: params.recovery,
		recoveryId: params.recoveryId,
		proposalIndex,
		proposer: params.proposer.publicKey,
		intentDigests: params.intentDigests,
		userPubkey: params.userPubkey,
		signatureScheme: params.signatureScheme,
		credential: params.credential,
	});
	const signature = await sendOne(ix, {
		...send,
		payer: params.proposer,
	});
	return { signature, proposal, proposalIndex };
}

async function defaultProposalIndex(connection: Connection, recovery: PublicKey): Promise<number> {
	const { readRecovery } = await import('./state');
	const account = await readRecovery(connection, recovery);
	if (!account) {
		throw new Error(`recovery PDA ${recovery.toBase58()} not found`);
	}
	return account.proposalCount;
}

export interface ApproveFlowParams extends Omit<ApproveParams, 'payer'> {
	/**
	 * Approver's keypair — defaults to `payer` if you want both auth and
	 * fee-payment in one signer. Pass a separate `feePayer` when sponsoring.
	 */
	approver: Signer;
	/** Optional fee sponsor; defaults to `approver`. */
	feePayer?: Signer;
}

/**
 * Build, sign, and confirm an `approve` tx. Returns the approval PDA.
 */
export async function approveAndConfirm(
	send: SendOptions,
	params: ApproveFlowParams,
): Promise<{ signature: string; approval: PublicKey }> {
	const feePayer = params.feePayer ?? params.approver;
	const { ix, approval } = buildApproveIx({
		recovery: params.recovery,
		proposal: params.proposal,
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

export interface ExecuteFlowParams extends Omit<ExecuteParams, 'payer'> {
	/**
	 * The signer that pays for the tx. Anyone can fire execute once a proposal
	 * reaches STATUS_APPROVED — no roster membership required.
	 */
	executor: Signer;
}

/**
 * Build, sign, and confirm an `execute` tx. Returns nothing useful — the
 * caller usually wants to read the proposal back to confirm STATUS_EXECUTED.
 */
export async function executeAndConfirm(
	send: SendOptions,
	params: ExecuteFlowParams,
): Promise<{ signature: string }> {
	const ix = buildExecuteIx({
		recovery: params.recovery,
		proposal: params.proposal,
		payer: params.executor.publicKey,
		txIndex: params.txIndex,
		messageBytes: params.messageBytes,
		coordinator: params.coordinator,
		messageApproval: params.messageApproval,
		dwallet: params.dwallet,
		callerProgram: params.callerProgram,
		cpiAuthority: params.cpiAuthority,
		dwalletProgram: params.dwalletProgram,
		messageApprovalBump: params.messageApprovalBump,
		cpiAuthorityBump: params.cpiAuthorityBump,
	});
	const signature = await sendOne(ix, {
		...send,
		payer: params.executor,
	});
	return { signature };
}

export { proposalPda };
