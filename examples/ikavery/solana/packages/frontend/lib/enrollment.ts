'use client';

import type { Wallet } from '@dynamic-labs/sdk-react-core';
import { isSolanaWallet } from '@dynamic-labs/solana';
import {
	buildApproveEnrollmentIx,
	buildExecuteEnrollmentIx,
	buildProposeEnrollmentIx,
	decodeEnrollmentProposal,
	enrollmentPda,
	ikaDwallet,
	IKAVERY_PROGRAM_ID,
	memberIdBytes,
	packSolanaMember,
	passkey,
	STATUS_APPROVED,
	type EnrollmentProposalAccount,
} from '@fesal-packages/ikavery-solana-sdk';
import {
	PublicKey,
	TransactionMessage,
	VersionedTransaction,
	type AddressLookupTableAccount,
	type Connection,
	type TransactionInstruction,
} from '@solana/web3.js';

import { ensureAltForRecovery } from '@/lib/alt';
import { produceAuth } from '@/lib/auth';
import type { StoredMember } from '@/store/setup';

const { IKA_DWALLET_PROGRAM_ID, coordinatorPda, cpiAuthorityPda } = ikaDwallet;

export type EnrollmentPhase =
	'idle' | 'ensuring-alt' | 'proposing' | 'approving' | 'awaiting-approvals' | 'executing' | 'done';

export interface EnrollmentDraft {
	/** Solana base58 address of the new member. */
	newMemberAddress: string;
	/** True ⇔ approver-only (no key share); false ⇔ key-holding. */
	approverOnly: boolean;
}

export interface ProposeEnrollmentResult {
	enrollment: PublicKey;
	enrollmentIndex: number;
	reachedThreshold: boolean;
	account: EnrollmentProposalAccount;
}

export interface ProposeEnrollmentParams {
	connection: Connection;
	primaryWallet: Wallet;
	/** The roster identity authorising the proposal — passkey or wallet. */
	voter: StoredMember;
	recovery: PublicKey;
	recoveryId: PublicKey;
	/** Per-recovery static accounts the ALT compresses (passed through). */
	dwalletPubkey: PublicKey;
	dwalletAccount: PublicKey;
	threshold: number;
	expectedIndex: number;
	draft: EnrollmentDraft;
	onProgress?: (phase: EnrollmentPhase) => void;
}

/**
 * Phase 1 — propose an enrollment + record the proposer's own approval.
 * Mirrors `proposeAndApprove` in `recover.ts`. On a 1-of-N roster the
 * caller can flow straight into `executeEnrollment`; otherwise it lands
 * in an "awaiting" state and other devices each call `approveEnrollment`
 * from the per-enrollment page.
 */
export async function proposeAndApproveEnrollment(
	params: ProposeEnrollmentParams,
): Promise<ProposeEnrollmentResult> {
	const {
		connection,
		primaryWallet,
		voter,
		recovery,
		recoveryId,
		dwalletPubkey,
		dwalletAccount,
		threshold,
		expectedIndex,
		draft,
		onProgress,
	} = params;

	if (!isSolanaWallet(primaryWallet)) {
		throw new Error("Connected wallet doesn't expose a Solana signer — reconnect to continue.");
	}
	const proposer = new PublicKey(primaryWallet.address);
	const signer = await primaryWallet.getSigner();

	let newMemberPubkey: PublicKey;
	try {
		newMemberPubkey = new PublicKey(draft.newMemberAddress.trim());
	} catch {
		throw new Error("New member address isn't a valid base58 Solana pubkey.");
	}

	onProgress?.('ensuring-alt');
	const { pda: cpiAuthority } = cpiAuthorityPda(IKAVERY_PROGRAM_ID);
	const { pda: coordinator } = coordinatorPda();
	const alt = await ensureAltForRecovery({
		connection,
		primaryWallet,
		payer: proposer,
		recovery,
		recoveryId,
		dwallet: dwalletPubkey,
		dwalletAccount,
		cpiAuthority,
		coordinator,
		dwalletProgram: IKA_DWALLET_PROGRAM_ID,
	});

	// ── Propose ───────────────────────────────────────────────────────────
	onProgress?.('proposing');
	const newMemberSlot = packSolanaMember(newMemberPubkey);
	const recoveryIdBytes = recoveryId.toBytes();
	// Challenge binds to the canonical member-id (`[scheme, ...pubkey]`), not
	// the raw pubkey — must match the on-chain handler which feeds `slot_id`
	// (i.e. the scheme-prefixed bytes) into `challenges::enroll_propose`.
	const proposeChallengeBytes = passkey.enrollProposeChallenge(
		recoveryIdBytes,
		memberIdBytes(newMemberSlot),
		expectedIndex,
	);
	const proposeAuth = await produceAuth({
		voter,
		proposer,
		challenge: proposeChallengeBytes,
	});
	const { ix: proposeIx, enrollment } = buildProposeEnrollmentIx({
		recovery,
		recoveryId,
		enrollmentIndex: expectedIndex,
		payer: proposer,
		newMember: newMemberSlot,
		// Solana ika pre-alpha has no re-encrypt CPI, so the program stores
		// this opaquely; mainnet would carry the new member's class-groups
		// public key here.
		newEncryptionKeyAddress: new Uint8Array(32).fill(0xee),
		additionApproverOnly: draft.approverOnly ? 1 : 0,
		credential: proposeAuth.credential,
	});
	await sendAndConfirm(
		connection,
		signer,
		proposer,
		[...proposeAuth.precompileIxs, proposeIx],
		[alt],
	);

	// ── Approve (proposer's own vote) ─────────────────────────────────────
	onProgress?.('approving');
	const approveChallengeBytes = passkey.enrollApproveChallenge(recoveryIdBytes, expectedIndex);
	const approveAuth = await produceAuth({
		voter,
		proposer,
		challenge: approveChallengeBytes,
	});
	const { ix: approveIx } = buildApproveEnrollmentIx({
		recovery,
		enrollment,
		payer: proposer,
		memberSlot: approveAuth.memberSlot,
		credential: approveAuth.credential,
	});
	await sendAndConfirm(
		connection,
		signer,
		proposer,
		[...approveAuth.precompileIxs, approveIx],
		[alt],
	);

	const account = await fetchEnrollment(connection, enrollment);
	return {
		enrollment,
		enrollmentIndex: expectedIndex,
		reachedThreshold: account.status === STATUS_APPROVED || account.approvalCount >= threshold,
		account,
	};
}

export interface ApproveEnrollmentAsMemberParams {
	connection: Connection;
	primaryWallet: Wallet;
	voter: StoredMember;
	recovery: PublicKey;
	recoveryId: PublicKey;
	enrollment: PublicKey;
	enrollmentIndex: number;
	dwalletPubkey: PublicKey;
	dwalletAccount: PublicKey;
	onProgress?: (phase: EnrollmentPhase) => void;
}

export async function approveEnrollmentAsMember(
	params: ApproveEnrollmentAsMemberParams,
): Promise<{ approval: PublicKey; signature: string }> {
	const {
		connection,
		primaryWallet,
		voter,
		recovery,
		recoveryId,
		enrollment,
		enrollmentIndex,
		dwalletPubkey,
		dwalletAccount,
		onProgress,
	} = params;

	if (!isSolanaWallet(primaryWallet)) {
		throw new Error("Connected wallet doesn't expose a Solana signer — reconnect to continue.");
	}
	const approver = new PublicKey(primaryWallet.address);
	const signer = await primaryWallet.getSigner();

	onProgress?.('ensuring-alt');
	const { pda: cpiAuthority } = cpiAuthorityPda(IKAVERY_PROGRAM_ID);
	const { pda: coordinator } = coordinatorPda();
	const alt = await ensureAltForRecovery({
		connection,
		primaryWallet,
		payer: approver,
		recovery,
		recoveryId,
		dwallet: dwalletPubkey,
		dwalletAccount,
		cpiAuthority,
		coordinator,
		dwalletProgram: IKA_DWALLET_PROGRAM_ID,
	});

	onProgress?.('approving');
	const challenge = passkey.enrollApproveChallenge(recoveryId.toBytes(), enrollmentIndex);
	const auth = await produceAuth({
		voter,
		proposer: approver,
		challenge,
	});
	const { ix, approval } = buildApproveEnrollmentIx({
		recovery,
		enrollment,
		payer: approver,
		memberSlot: auth.memberSlot,
		credential: auth.credential,
	});
	const signature = await sendAndConfirm(
		connection,
		signer,
		approver,
		[...auth.precompileIxs, ix],
		[alt],
	);
	return { approval, signature };
}

export interface ExecuteEnrollmentParams {
	connection: Connection;
	primaryWallet: Wallet;
	recovery: PublicKey;
	enrollment: PublicKey;
	onProgress?: (phase: EnrollmentPhase) => void;
}

export async function executeEnrollment(
	params: ExecuteEnrollmentParams,
): Promise<{ signature: string }> {
	const { connection, primaryWallet, recovery, enrollment, onProgress } = params;
	if (!isSolanaWallet(primaryWallet)) {
		throw new Error("Connected wallet doesn't expose a Solana signer — reconnect via the widget.");
	}
	const executor = new PublicKey(primaryWallet.address);
	const signer = await primaryWallet.getSigner();

	onProgress?.('executing');
	const ix = buildExecuteEnrollmentIx({
		recovery,
		enrollment,
		payer: executor,
	});
	const signature = await sendAndConfirm(connection, signer, executor, [ix]);
	return { signature };
}

async function fetchEnrollment(
	connection: Connection,
	enrollment: PublicKey,
): Promise<EnrollmentProposalAccount> {
	const info = await connection.getAccountInfo(enrollment, 'confirmed');
	if (!info) {
		throw new Error(`Enrollment ${enrollment.toBase58()} not found`);
	}
	return decodeEnrollmentProposal(info.data);
}

interface SolanaSigner {
	signTransaction(tx: VersionedTransaction): Promise<VersionedTransaction>;
}

async function sendAndConfirm(
	connection: Connection,
	signer: SolanaSigner,
	payer: PublicKey,
	instructions: TransactionInstruction[],
	lookupTables: AddressLookupTableAccount[] = [],
): Promise<string> {
	const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
	const message = new TransactionMessage({
		payerKey: payer,
		recentBlockhash: blockhash,
		instructions,
	}).compileToV0Message(lookupTables);
	const tx = new VersionedTransaction(message);
	const signed = await signer.signTransaction(tx);
	const sig = await connection.sendRawTransaction(signed.serialize(), {
		skipPreflight: false,
		preflightCommitment: 'confirmed',
	});
	await connection.confirmTransaction(
		{ signature: sig, blockhash, lastValidBlockHeight },
		'confirmed',
	);
	return sig;
}

export { enrollmentPda };
