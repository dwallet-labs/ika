'use client';

import type { Wallet } from '@dynamic-labs/sdk-react-core';
import { isSolanaWallet } from '@dynamic-labs/solana';
import { solanaIntentDigest } from '@fesal-packages/ikavery-core';
import {
	buildApproveIx,
	buildExecuteIx,
	buildProposeIx,
	decodeProposal,
	ikaDwallet,
	IKAVERY_PROGRAM_ID,
	MAX_MESSAGE_BYTES,
	passkey,
	proposalPda,
	STATUS_APPROVED,
	STATUS_EXECUTED,
	type ProposalAccount,
} from '@fesal-packages/ikavery-solana-sdk';
import { keccak_256 } from '@noble/hashes/sha3';
import {
	PublicKey,
	TransactionMessage,
	VersionedTransaction,
	type AddressLookupTableAccount,
	type Connection,
	type TransactionInstruction,
} from '@solana/web3.js';
import bs58 from 'bs58';

import { ensureAltForRecovery } from '@/lib/alt';
import { produceAuth } from '@/lib/auth';
import { ikaPresignAndSignCurve25519 } from '@/lib/ika-web';
import {
	hexToBytes,
	saveSweepBundle,
	type DkgBundle,
	type SerializedTokenAccount,
	type SweepBundle,
} from '@/lib/storage';
import type { StoredMember } from '@/store/setup';

const {
	CURVE_CURVE25519,
	IKA_DWALLET_PROGRAM_ID,
	SIG_SCHEME_EDDSA_SHA512,
	coordinatorPda,
	cpiAuthorityPda,
	dwalletPda,
	messageApprovalPda,
} = ikaDwallet;

/**
 * The on-chain `dwallet_account_min_balance` after a sweep — leave this
 * many lamports on the dWallet so the System Program transfer succeeds
 * without closing the account. Same value used in Sui's sweep planner.
 */
const DWALLET_RENT_RESERVE = 890_880;

export type RecoverPhase =
	| 'idle'
	| 'ensuring-alt'
	| 'proposing'
	| 'approving'
	| 'awaiting-approvals'
	| 'executing'
	| 'signing'
	| 'broadcasting'
	| 'done';

export interface RecoverPlan {
	/** dWallet pubkey (also the on-chain "from" address). */
	dwalletPubkey: PublicKey;
	/** dWallet PDA on the dWallet program (the signing authority). */
	dwalletAccount: PublicKey;
	destination: PublicKey;
	/** Lamports the SOL leg of the sweep will move (balance minus rent reserve). */
	sweepLamports: number;
	/** dWallet's current SOL balance. */
	dwalletBalance: number;
}

export interface ProposeResult {
	proposal: PublicKey;
	proposalIndex: number;
	/** True iff the proposer's auto-approve crossed the threshold. */
	reachedThreshold: boolean;
	/** Final on-chain proposal state after propose+approve. */
	proposalAccount: ProposalAccount;
	/** Bundle metadata stashed for executeAndBroadcast. */
	bundle: SweepBundle;
}

export interface BroadcastResult {
	/** One execute tx signature per bundle position. */
	executeSigs: string[];
	/** One broadcast (sweep) tx signature per bundle position. */
	broadcastSigs: string[];
	recipient: PublicKey;
	totalLamports: number;
}

export interface PlanRecoveryParams {
	connection: Connection;
	dwalletPubkey: PublicKey;
	destination: PublicKey;
}

/** Compute the lamport amount the SOL leg of the sweep would move. */
export async function planRecovery(params: PlanRecoveryParams): Promise<RecoverPlan> {
	const dwalletBalance = await params.connection.getBalance(params.dwalletPubkey, 'confirmed');
	const sweepLamports = dwalletBalance - DWALLET_RENT_RESERVE;
	if (sweepLamports <= 0) {
		throw new Error(`dWallet has only ${dwalletBalance} lamports — fund it before sweeping.`);
	}
	const { pda: dwalletAccount } = dwalletPda(CURVE_CURVE25519, params.dwalletPubkey.toBytes());
	return {
		dwalletPubkey: params.dwalletPubkey,
		dwalletAccount,
		destination: params.destination,
		sweepLamports,
		dwalletBalance,
	};
}

export interface ProposeAndApproveParams {
	connection: Connection;
	primaryWallet: Wallet;
	/** The roster identity authorising the proposal — passkey or wallet. */
	voter: StoredMember;
	recovery: PublicKey;
	recoveryId: PublicKey;
	threshold: number;
	/**
	 * Bundle metadata used to (a) compute per-tx digests now and (b) rebuild
	 * the sweep messages with a fresh blockhash at execute time.
	 */
	bundle: {
		/** dWallet pubkey — fee payer for every sweep tx. */
		source: PublicKey;
		destination: PublicKey;
		/** dWallet's SOL balance at propose time. */
		solBalanceLamports: bigint;
		feeReserveLamports: bigint;
		tokenAccounts: SerializedTokenAccount[];
		/** Pre-built v0 message bytes (one per bundle tx) — used for digesting. */
		sweepMessages: Uint8Array[];
	};
	dwalletPubkey: PublicKey;
	dwalletAccount: PublicKey;
	/** Current `Recovery.proposal_count` — the next proposal's index. */
	expectedProposalIndex: number;
	onProgress?: (phase: RecoverPhase, detail?: string) => void;
}

/**
 * Phase 1 — submit one propose tx that commits to a bundle of N intent
 * digests, then auto-approve as the proposer. Single proposal carries the
 * whole bundle, Sui-parity.
 */
export async function proposeAndApprove(params: ProposeAndApproveParams): Promise<ProposeResult> {
	const {
		connection,
		primaryWallet,
		voter,
		recovery,
		recoveryId,
		threshold,
		bundle,
		dwalletPubkey,
		dwalletAccount,
		expectedProposalIndex,
		onProgress,
	} = params;

	if (!isSolanaWallet(primaryWallet)) {
		throw new Error("Connected wallet doesn't expose a Solana signer — reconnect to continue.");
	}
	if (bundle.sweepMessages.length === 0) {
		throw new Error('proposeAndApprove: bundle must contain at least one tx');
	}
	const proposer = new PublicKey(primaryWallet.address);
	const signer = await primaryWallet.getSigner();

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

	// Compute one intent digest per tx in the bundle. The credential commits
	// to all N digests via `bundle_hash_from_digests` on chain.
	const intentDigests = bundle.sweepMessages.map((msg) => solanaIntentDigest(msg));

	// ── Propose ───────────────────────────────────────────────────────────
	onProgress?.('proposing');
	const recoveryIdBytes = recoveryId.toBytes();
	const proposeBundleHash = passkey.bundleHashFromDigests(intentDigests);
	const proposeChallengeBytes = passkey.proposeChallenge(
		recoveryIdBytes,
		proposeBundleHash,
		expectedProposalIndex,
	);
	const proposeAuth = await produceAuth({
		voter,
		proposer,
		challenge: proposeChallengeBytes,
	});
	const { ix: proposeIx, proposal } = buildProposeIx({
		recovery,
		recoveryId,
		proposalIndex: expectedProposalIndex,
		proposer,
		intentDigests,
		userPubkey: dwalletPubkey.toBytes(),
		signatureScheme: SIG_SCHEME_EDDSA_SHA512,
		credential: proposeAuth.credential,
	});
	await sendAndConfirm(
		connection,
		signer,
		proposer,
		[...proposeAuth.precompileIxs, proposeIx],
		[alt],
	);

	// ── Approve (voter's own vote) ────────────────────────────────────────
	onProgress?.('approving');
	const approveChallengeBytes = passkey.approveChallenge(recoveryIdBytes, expectedProposalIndex);
	const approveAuth = await produceAuth({
		voter,
		proposer,
		challenge: approveChallengeBytes,
	});
	const { ix: approveIx } = buildApproveIx({
		recovery,
		proposal,
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

	// Stash the bundle metadata so any device with the DKG bundle can rebuild
	// the same per-tx messages at broadcast time. The on-chain intent digest
	// gates structural equivalence; only the blockhash refreshes.
	const sweepBundle: SweepBundle = {
		recovery: recovery.toBase58(),
		proposalAddresses: [proposal.toBase58()],
		proposalIndexes: [expectedProposalIndex],
		source: bundle.source.toBase58(),
		destination: bundle.destination.toBase58(),
		solBalanceLamports: bundle.solBalanceLamports.toString(),
		feeReserveLamports: bundle.feeReserveLamports.toString(),
		tokenAccounts: bundle.tokenAccounts,
		proposedAt: Date.now(),
	};
	await saveSweepBundle(sweepBundle);

	// Read back the proposal so the caller knows whether we cleared the
	// threshold (1-of-1 happy path) or have to wait for more approvals.
	const proposalAccount = await fetchProposal(connection, proposal);
	return {
		proposal,
		proposalIndex: expectedProposalIndex,
		reachedThreshold:
			proposalAccount.status === STATUS_APPROVED || proposalAccount.approvalCount >= threshold,
		proposalAccount,
		bundle: sweepBundle,
	};
}

export interface ApproveOneParams {
	connection: Connection;
	primaryWallet: Wallet;
	voter: StoredMember;
	recovery: PublicKey;
	recoveryId: PublicKey;
	proposal: PublicKey;
	proposalIndex: number;
	dwalletPubkey: PublicKey;
	dwalletAccount: PublicKey;
	onProgress?: (phase: RecoverPhase, detail?: string) => void;
}

export async function approveAsMember(
	params: ApproveOneParams,
): Promise<{ approval: PublicKey; signature: string }> {
	const {
		connection,
		primaryWallet,
		voter,
		recovery,
		recoveryId,
		proposal,
		proposalIndex,
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
	const challenge = passkey.approveChallenge(recoveryId.toBytes(), proposalIndex);
	const auth = await produceAuth({
		voter,
		proposer: approver,
		challenge,
	});
	const { ix, approval } = buildApproveIx({
		recovery,
		proposal,
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

export interface BroadcastParams {
	connection: Connection;
	primaryWallet: Wallet;
	recovery: PublicKey;
	recoveryId: PublicKey;
	proposal: PublicKey;
	/** DKG attestation reused across every tx in the bundle. */
	dkg: DkgBundle;
	/** Bundle metadata stashed at propose time. */
	bundle: SweepBundle;
	/**
	 * Pre-built v0 message bytes for each tx in the bundle (matching the
	 * bundle's intent digests). Caller rebuilds these from `bundle` so the
	 * blockhash is fresh; this helper just signs + broadcasts.
	 */
	sweepMessages: Uint8Array[];
	onProgress?: (phase: RecoverPhase, detail?: string) => void;
}

/**
 * Phase 2 — for each tx in the proposal's bundle: fire `execute(tx_index)`
 * to write a MessageApproval, drive gRPC sign over the message bytes,
 * splice the EdDSA signature into a fresh v0 transaction, and broadcast.
 *
 * Per-tx idempotency lives on chain: the proposal's `executed_bitmap` set
 * bit prevents re-firing CPIs. Broadcast itself is naturally idempotent
 * because Solana rejects duplicate signatures.
 */
export async function executeAndBroadcast(params: BroadcastParams): Promise<BroadcastResult> {
	const {
		connection,
		primaryWallet,
		recovery,
		recoveryId,
		proposal,
		dkg,
		bundle,
		sweepMessages,
		onProgress,
	} = params;

	if (!isSolanaWallet(primaryWallet)) {
		throw new Error("Connected wallet doesn't expose a Solana signer — reconnect to continue.");
	}
	if (sweepMessages.length === 0) {
		throw new Error('executeAndBroadcast: bundle is empty');
	}
	const executor = new PublicKey(primaryWallet.address);
	const signer = await primaryWallet.getSigner();
	const dwalletPubkey = new PublicKey(dkg.dwalletPubkey);
	const dwalletAccount = new PublicKey(dkg.dwalletAccount);
	const destination = new PublicKey(bundle.destination);

	onProgress?.('ensuring-alt');
	const { pda: cpiAuthority, bump: cpiAuthorityBump } = cpiAuthorityPda(IKAVERY_PROGRAM_ID);
	const { pda: coordinator } = coordinatorPda();
	const alt = await ensureAltForRecovery({
		connection,
		primaryWallet,
		payer: executor,
		recovery,
		recoveryId,
		dwallet: dwalletPubkey,
		dwalletAccount,
		cpiAuthority,
		coordinator,
		dwalletProgram: IKA_DWALLET_PROGRAM_ID,
	});

	const executeSigs: string[] = [];
	const broadcastSigs: string[] = [];
	let totalLamports = 0;

	for (let txIndex = 0; txIndex < sweepMessages.length; txIndex++) {
		const finalMsg = sweepMessages[txIndex] as Uint8Array;
		onProgress?.('executing', `tx ${txIndex + 1} of ${sweepMessages.length}: writing approval`);
		const messageDigest = keccak_256(finalMsg);
		const { pda: messageApproval, bump: messageApprovalBump } = messageApprovalPda(
			CURVE_CURVE25519,
			dwalletPubkey.toBytes(),
			SIG_SCHEME_EDDSA_SHA512,
			messageDigest,
		);
		const executeIx = buildExecuteIx({
			recovery,
			proposal,
			payer: executor,
			txIndex,
			messageBytes: finalMsg,
			coordinator,
			messageApproval,
			dwallet: dwalletAccount,
			callerProgram: IKAVERY_PROGRAM_ID,
			cpiAuthority,
			dwalletProgram: IKA_DWALLET_PROGRAM_ID,
			messageApprovalBump,
			cpiAuthorityBump,
		});
		const executeSig = await sendAndConfirm(connection, signer, executor, [executeIx], [alt]);
		executeSigs.push(executeSig);

		onProgress?.('signing', `tx ${txIndex + 1} of ${sweepMessages.length}: gRPC sign`);
		const txSigBytes = bs58.decode(executeSig);
		const sigBytes = await ikaPresignAndSignCurve25519(
			new PublicKey(dkg.senderPubkey).toBytes(),
			{
				attestationData: hexToBytes(dkg.attestationDataHex),
				networkSignature: hexToBytes(dkg.networkSignatureHex),
				networkPubkey: hexToBytes(dkg.networkPubkeyHex),
			},
			finalMsg,
			txSigBytes,
		);
		if (sigBytes.length !== 64) {
			throw new Error(`expected 64-byte EdDSA sig, got ${sigBytes.length}`);
		}

		onProgress?.('broadcasting', `tx ${txIndex + 1} of ${sweepMessages.length}: broadcast`);
		const sweepTx = VersionedTransaction.deserialize(
			new Uint8Array([0x01, ...sigBytes, ...finalMsg]),
		);
		const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
		const broadcastSig = await connection.sendRawTransaction(sweepTx.serialize(), {
			skipPreflight: true,
			preflightCommitment: 'confirmed',
		});
		await connection.confirmTransaction(
			{ signature: broadcastSig, blockhash, lastValidBlockHeight },
			'confirmed',
		);
		broadcastSigs.push(broadcastSig);
	}

	// Surface the SOL leg's lamport count so the result block can show a
	// recognisable number; the destination receives any SPL totals from
	// their respective ATAs.
	totalLamports = Number(BigInt(bundle.solBalanceLamports) - BigInt(bundle.feeReserveLamports));

	onProgress?.('done');
	return {
		executeSigs,
		broadcastSigs,
		recipient: destination,
		totalLamports,
	};
}

async function fetchProposal(
	connection: Connection,
	proposal: PublicKey,
): Promise<ProposalAccount> {
	const info = await connection.getAccountInfo(proposal, 'confirmed');
	if (!info) throw new Error(`Proposal ${proposal.toBase58()} not found`);
	return decodeProposal(info.data);
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

export function isExecuted(account: ProposalAccount): boolean {
	return account.status === STATUS_EXECUTED;
}

export function isApproved(account: ProposalAccount): boolean {
	return account.status === STATUS_APPROVED;
}

export { proposalPda };

/**
 * Rebuild the sweep bundle's per-tx messages from stashed metadata + a
 * fresh blockhash. The structural intent digest excludes the blockhash, so
 * these new bytes commit to the same intent stored on chain.
 */
export async function rebuildBundleMessages(
	connection: Connection,
	bundle: SweepBundle,
): Promise<Uint8Array[]> {
	const { buildSweepBundle } = await import('@fesal-packages/ikavery-core');
	const source = new PublicKey(bundle.source);
	const destination = new PublicKey(bundle.destination);
	const tokenAccounts = bundle.tokenAccounts.map((t) => ({
		mint: new PublicKey(t.mint),
		tokenAccount: new PublicKey(t.tokenAccount),
		amount: BigInt(t.amount),
		decimals: t.decimals,
		programId: new PublicKey(t.programId),
	}));
	const { blockhash } = await connection.getLatestBlockhash('confirmed');
	return buildSweepBundle({
		source,
		destination,
		solBalance: BigInt(bundle.solBalanceLamports),
		feeReserveLamports: BigInt(bundle.feeReserveLamports),
		tokenAccounts,
		recentBlockhash: blockhash,
		maxSerializedMessageBytes: MAX_MESSAGE_BYTES,
	});
}
