'use client';

import type { Wallet } from '@dynamic-labs/sdk-react-core';
import { isSolanaWallet } from '@dynamic-labs/solana';
import {
	buildApproveRosterChangeIx,
	buildExecuteRosterChangeIx,
	buildProposeRosterChangeIx,
	buildStageRosterChangePayloadIx,
	decodeRosterChangeProposal,
	ikaDwallet,
	IKAVERY_PROGRAM_ID,
	memberIdBytes,
	packSolanaMember,
	passkey,
	rosterChangePda,
	STATUS_APPROVED,
	type RosterChangeProposalAccount,
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

export type RosterPhase =
	'idle' | 'ensuring-alt' | 'proposing' | 'approving' | 'awaiting-approvals' | 'executing' | 'done';

export interface RosterDraft {
	/** New members' base58 Solana addresses. */
	additions: string[];
	/** Indexes (into the current member list) to remove. */
	removalIndexes: number[];
	/** New threshold; null to keep current. */
	newThreshold: number | null;
	/** Bit `i` ⇔ `additions[i]` is approver-only. */
	approverOnlyBitmap: number;
}

export interface ProposeRosterResult {
	rosterChange: PublicKey;
	rosterChangeIndex: number;
	reachedThreshold: boolean;
	account: RosterChangeProposalAccount;
}

export interface ProposeRosterParams {
	connection: Connection;
	primaryWallet: Wallet;
	/** The roster identity authorising the proposal — passkey or wallet. */
	voter: StoredMember;
	recovery: PublicKey;
	recoveryId: PublicKey;
	/** Per-recovery static accounts the ALT compresses. */
	dwalletPubkey: PublicKey;
	dwalletAccount: PublicKey;
	/** Current roster — used to translate `removalIndexes` into member slots. */
	currentMembers: Uint8Array[];
	threshold: number;
	expectedIndex: number;
	draft: RosterDraft;
	onProgress?: (phase: RosterPhase) => void;
}

/** Phase 1 — propose roster change + auto-approve as the proposer. */
export async function proposeAndApproveRoster(
	params: ProposeRosterParams,
): Promise<ProposeRosterResult> {
	const {
		connection,
		primaryWallet,
		voter,
		recovery,
		recoveryId,
		dwalletPubkey,
		dwalletAccount,
		currentMembers,
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

	if (draft.additions.length + draft.removalIndexes.length === 0 && draft.newThreshold === null) {
		throw new Error('Roster change is empty — pick at least one edit.');
	}

	// Pack additions; reject duplicates against the current set.
	const additionSlots: Uint8Array[] = [];
	const seen = new Set<string>();
	for (const addr of draft.additions) {
		const trimmed = addr.trim();
		if (!trimmed) continue;
		let pubkey: PublicKey;
		try {
			pubkey = new PublicKey(trimmed);
		} catch {
			throw new Error(`"${trimmed}" isn't a valid base58 Solana address.`);
		}
		if (seen.has(pubkey.toBase58())) {
			throw new Error(`Duplicate addition: ${pubkey.toBase58()}`);
		}
		seen.add(pubkey.toBase58());
		const slot = packSolanaMember(pubkey);
		if (currentMembers.some((m) => idEq(memberIdBytes(m), memberIdBytes(slot)))) {
			throw new Error(`${pubkey.toBase58()} is already on the roster.`);
		}
		additionSlots.push(slot);
	}

	// Resolve removals from indexes.
	const removalSlots: Uint8Array[] = [];
	for (const idx of draft.removalIndexes) {
		const slot = currentMembers[idx];
		if (!slot) throw new Error(`Removal index ${idx} out of range.`);
		removalSlots.push(slot);
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

	// Canonical roster-change payload hash — matches `auth/challenges.rs`'s
	// `roster_change_payload`. The on-chain handler treats payload_hash as an
	// opaque per-op challenge digest, but using the canonical form lets a
	// future indexer reconcile assertions across chains.
	const removalIds = removalSlots.map((slot) => memberIdBytes(slot));
	// When the threshold isn't changing, the canonical hash uses 0 in the
	// threshold slot — matches the on-chain stage handler, which writes
	// `args.new_threshold` (encoded as 0 by the SDK when unset) into its
	// own `roster_change_payload` call. Passing `currentThreshold` here
	// would diverge and break the propose-time `staging.payload_hash`
	// check (IntentDigestMismatch).
	const hasNewThreshold = draft.newThreshold !== null;
	const newThresholdValue = hasNewThreshold ? (draft.newThreshold ?? 0) : 0;
	const payloadHash = passkey.rosterChangePayloadHash(
		removalIds,
		newThresholdValue,
		hasNewThreshold,
	);

	// ── Stage payload ─────────────────────────────────────────────────────
	// The bulky additions/removals/threshold get buffered into a per-index
	// PDA so the credential-bearing propose tx stays under the 1232-byte
	// packet cap with the secp256r1 precompile.
	onProgress?.('proposing');
	const { ix: stageIx } = buildStageRosterChangePayloadIx({
		recovery,
		recoveryId,
		rosterChangeIndex: expectedIndex,
		payer: proposer,
		additions: additionSlots,
		removals: removalSlots,
		additionApproverOnlyBitmap: draft.approverOnlyBitmap,
		newThreshold: draft.newThreshold ?? undefined,
	});
	await sendAndConfirm(connection, signer, proposer, [stageIx], [alt]);

	// ── Propose ───────────────────────────────────────────────────────────
	const recoveryIdBytes = recoveryId.toBytes();
	const proposeChallenge = passkey.rosterChangeProposeChallenge(
		recoveryIdBytes,
		payloadHash,
		expectedIndex,
	);
	const proposeAuth = await produceAuth({
		voter,
		proposer,
		challenge: proposeChallenge,
	});
	const { ix: proposeIx, rosterChange } = buildProposeRosterChangeIx({
		recovery,
		recoveryId,
		rosterChangeIndex: expectedIndex,
		payer: proposer,
		payloadHash,
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
	const approveChallenge = passkey.rosterChangeApproveChallenge(recoveryIdBytes, expectedIndex);
	const approveAuth = await produceAuth({
		voter,
		proposer,
		challenge: approveChallenge,
	});
	const { ix: approveIx } = buildApproveRosterChangeIx({
		recovery,
		rosterChange,
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

	const account = await fetchRosterChange(connection, rosterChange);
	return {
		rosterChange,
		rosterChangeIndex: expectedIndex,
		reachedThreshold: account.status === STATUS_APPROVED || account.approvalCount >= threshold,
		account,
	};
}

export interface ApproveRosterAsMemberParams {
	connection: Connection;
	primaryWallet: Wallet;
	voter: StoredMember;
	recovery: PublicKey;
	recoveryId: PublicKey;
	rosterChange: PublicKey;
	rosterChangeIndex: number;
	dwalletPubkey: PublicKey;
	dwalletAccount: PublicKey;
	onProgress?: (phase: RosterPhase) => void;
}

export async function approveRosterAsMember(
	params: ApproveRosterAsMemberParams,
): Promise<{ approval: PublicKey; signature: string }> {
	const {
		connection,
		primaryWallet,
		voter,
		recovery,
		recoveryId,
		rosterChange,
		rosterChangeIndex,
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
	const challenge = passkey.rosterChangeApproveChallenge(recoveryId.toBytes(), rosterChangeIndex);
	const auth = await produceAuth({
		voter,
		proposer: approver,
		challenge,
	});
	const { ix, approval } = buildApproveRosterChangeIx({
		recovery,
		rosterChange,
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

export interface ExecuteRosterParams {
	connection: Connection;
	primaryWallet: Wallet;
	recovery: PublicKey;
	rosterChange: PublicKey;
	onProgress?: (phase: RosterPhase) => void;
}

export async function executeRoster(params: ExecuteRosterParams): Promise<{ signature: string }> {
	const { connection, primaryWallet, recovery, rosterChange, onProgress } = params;
	if (!isSolanaWallet(primaryWallet)) {
		throw new Error("Connected wallet doesn't expose a Solana signer — reconnect to continue.");
	}
	const executor = new PublicKey(primaryWallet.address);
	const signer = await primaryWallet.getSigner();

	onProgress?.('executing');
	const ix = buildExecuteRosterChangeIx({
		recovery,
		rosterChange,
		payer: executor,
	});
	const signature = await sendAndConfirm(connection, signer, executor, [ix]);
	return { signature };
}

async function fetchRosterChange(
	connection: Connection,
	rosterChange: PublicKey,
): Promise<RosterChangeProposalAccount> {
	const info = await connection.getAccountInfo(rosterChange, 'confirmed');
	if (!info) {
		throw new Error(`Roster change ${rosterChange.toBase58()} not found`);
	}
	return decodeRosterChangeProposal(info.data);
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

function idEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

export { rosterChangePda };
