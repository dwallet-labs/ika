import {
	assembleSignedTransaction,
	extractIntents,
	intentHash,
	previewMessageBytes,
	rebuildSweepFromIntents,
	type BundlePreview,
	type SweepIntent,
} from '@fesal-packages/ikavery-core';
import {
	CoordinatorInnerModule,
	createUserSignMessageWithPublicOutput,
	Curve,
	Hash,
	parseSignatureFromSignOutput,
	SessionsManagerModule,
	SignatureAlgorithm,
	type EncryptedUserSecretKeyShare,
	type ImportedKeyDWallet,
	type UserShareEncryptionKeys,
} from '@ika.xyz/sdk';
import { bcs } from '@mysten/sui/bcs';
import type { Keypair } from '@mysten/sui/cryptography';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import type { Connection } from '@solana/web3.js';

import type { RecoveryClient } from '../client';
import {
	buildApproveChallenge,
	buildExecuteChallenge,
	buildProposeChallenge,
} from '../crypto/challenges';
import { executorFromKeypair, type TransactionExecutor } from '../executor';
import * as moveRecovery from '../generated/recovery/recovery';
import { buildCredential, type AuthSigner } from '../move/credential';
import { readRecoveryState } from './state';

const DEFAULT_IKA_FEE = 1_000_000n;
const DEFAULT_SUI_FEE = 1_000_000n;
const DEFAULT_TIMEOUT_MS = 600_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;

// ===== proposeRecovery =====

export interface ProposeRecoveryParams {
	/** Solana sweep messages, in execution order — built via `buildSweepBundle`. */
	sweepMessages: Uint8Array[];
	/** Caller's auth: signs the operation challenge with one of the four credential schemes. */
	authSigner: AuthSigner;
	/**
	 * Pass a `Keypair` for CLI scripts (auto-wrapped) or a {@link TransactionExecutor}
	 * for browser-wallet integrations where the signer lives behind an adapter.
	 */
	gasSigner: Keypair | TransactionExecutor;
}

export interface ProposeRecoveryResult {
	proposalId: bigint;
	digest: string;
	/** `sha256(BCS(vector<SweepIntent>))` — the canonical proposal identifier. */
	intentHash: Uint8Array;
}

/**
 * Phase-1 of the sign-at-execute flow: parse the bundle into structural
 * intents (off-chain mirror of `sweep_intent::from_message_bytes`), commit
 * to them via the propose challenge, and submit. The Move side reserves
 * one presign per tx into the proposal but does NOT call `request_future_sign`,
 * so the bundle is not yet bound to any specific recent blockhash.
 *
 * No `request_future_sign` means propose pays no per-message Ika/Sui fees.
 */
export async function proposeRecovery(
	client: RecoveryClient,
	params: ProposeRecoveryParams,
): Promise<ProposeRecoveryResult> {
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);
	const state = await readRecoveryState(client);
	const n = params.sweepMessages.length;

	if (n === 0) throw new Error('proposeRecovery: sweepMessages is empty');
	if (BigInt(n) > state.presignCount) {
		throw new Error(
			`proposeRecovery: bundle requires ${n} presigns, only ${state.presignCount} warm`,
		);
	}

	// Project bundle to canonical intents and hash them. Throws on any unknown
	// program / instruction — same conditions Move would abort on.
	const intents = extractIntents(params.sweepMessages);
	const intentH = intentHash(intents);

	const challenge = buildProposeChallenge(client.ref.recoveryId, intentH, state.nonce);
	const credentialInput = await params.authSigner.sign(challenge);

	const tx = new Transaction();
	const sweepArg = tx.pure(
		bcs.vector(bcs.vector(bcs.u8())).serialize(params.sweepMessages.map((m) => Array.from(m))),
	);
	const credArg = buildCredential(tx, client.ref.packageId, credentialInput);

	tx.add(
		moveRecovery.propose({
			package: client.ref.packageId,
			arguments: [client.ref.recoveryId, sweepArg, credArg],
		}),
	);

	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(`proposeRecovery: failed: ${JSON.stringify(result.FailedTransaction.status)}`);
	}
	return {
		proposalId: state.nextProposalId,
		digest: result.Transaction.digest,
		intentHash: intentH,
	};
}

// ===== approveRecovery =====

export interface ApproveRecoveryParams {
	proposalId: bigint;
	authSigner: AuthSigner;
	gasSigner: Keypair | TransactionExecutor;
}

export async function approveRecovery(
	client: RecoveryClient,
	params: ApproveRecoveryParams,
): Promise<{ digest: string }> {
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);

	const challenge = buildApproveChallenge(client.ref.recoveryId, params.proposalId);
	const credentialInput = await params.authSigner.sign(challenge);

	const tx = new Transaction();
	const credArg = buildCredential(tx, client.ref.packageId, credentialInput);
	client.move.approve({
		self: client.ref.recoveryId,
		proposalId: params.proposalId,
		cred: credArg,
	})(tx);

	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(`approveRecovery: failed: ${JSON.stringify(result.FailedTransaction.status)}`);
	}
	return { digest: result.Transaction.digest };
}

// ===== executeRecovery =====

export type ExecuteRecoveryPhase =
	| 'reading-proposal'
	| 'fetching-blockhash'
	| 'decrypting-share'
	| 'waiting-for-presigns'
	| 'building-signatures'
	| 'auth-ceremony'
	| 'submitting-execute'
	| 'waiting-for-sign-sessions'
	| 'assembling';

export interface ExecuteRecoveryParams {
	proposalId: bigint;
	/** Executor's auth credential (must be a member). */
	authSigner: AuthSigner;
	/** Encryption identity holding a decryptable share for the imported-key dWallet. */
	userShareEncryptionKeys: UserShareEncryptionKeys;
	/** The executor's encrypted-share object — used to decrypt the centralized share locally. */
	encryptedUserShare: EncryptedUserSecretKeyShare;
	/** Solana RPC connection — used to fetch a fresh recent blockhash. */
	solanaConnection: Connection;
	gasSigner: Keypair | TransactionExecutor;
	ikaFeePerMessage?: bigint;
	suiFeePerMessage?: bigint;
	/** Polling timeout per sign session. Default 10 minutes. */
	timeoutMs?: number;
	pollIntervalMs?: number;
	/**
	 * Fine-grained progress callback. `index` and `total` are populated for
	 * the per-message `waiting-for-sign-sessions` phase so the UI can show a
	 * counter — every other phase calls it once with no index.
	 */
	onProgress?: (phase: ExecuteRecoveryPhase, detail?: { index: number; total: number }) => void;
}

export interface ExecuteRecoveryResult {
	digest: string;
	/** One signed Solana transaction per sweep message, in original order. */
	signedTransactions: Uint8Array[];
	signIds: string[];
	/** The fresh sweep messages built at execute time (with current blockhash). */
	sweepMessages: Uint8Array[];
}

/**
 * Phase-2 of the sign-at-execute flow.
 *
 *   1. Read stored `sweep_intents` from the proposal.
 *   2. Fetch a current Solana blockhash.
 *   3. Rebuild fresh sweep messages from the intents — same instructions and
 *      account ordering as the original, just with the new blockhash.
 *   4. Decrypt the executor's user share, then for each fresh message create
 *      a per-message centralized signature.
 *   5. Submit `recovery::execute` with the fresh messages + sigs. Move
 *      re-derives the intent from each message and aborts unless it matches
 *      the stored intent at the same index.
 *   6. Wait for the resulting `Sign` sessions to complete and assemble
 *      signed Solana transactions.
 */
export async function executeRecovery(
	client: RecoveryClient,
	params: ExecuteRecoveryParams,
): Promise<ExecuteRecoveryResult> {
	const ikaClient = client.ikaClient;
	const executor: TransactionExecutor =
		'signAndExecute' in params.gasSigner
			? params.gasSigner
			: executorFromKeypair(params.gasSigner, client.suiClient);
	const phase = params.onProgress ?? (() => {});

	phase('reading-proposal');
	const state = await readRecoveryState(client);
	const proposal = await readProposal(client, params.proposalId);
	const storedIntents = proposal.sweep_intents.map(decodeStoredIntent);
	const n = storedIntents.length;

	// Rebuild messages with a fresh blockhash. Sanity-check our rebuild against
	// the stored intents before sending — the chain will redo this check, but
	// failing locally gives a much better error.
	phase('fetching-blockhash');
	const { blockhash } = await params.solanaConnection.getLatestBlockhash('confirmed');
	const sweepMessages = rebuildSweepFromIntents(storedIntents, blockhash);
	const rebuiltIntents = extractIntents(sweepMessages);
	for (let i = 0; i < n; i++) {
		const a = intentHash([storedIntents[i]!]);
		const b = intentHash([rebuiltIntents[i]!]);
		if (!byteEq(a, b)) {
			throw new Error(
				`executeRecovery: rebuilt intent #${i} doesn't match stored — likely an SDK/Move drift`,
			);
		}
	}

	// Decrypt our share, fetch dWallet + presigns, and produce per-message
	// centralized signatures.
	phase('decrypting-share');
	const dWallet = (await ikaClient.getDWalletInParticularState(
		state.importedKeyDwalletId,
		'Active',
	)) as ImportedKeyDWallet;
	if (!dWallet.state.Active) {
		throw new Error('executeRecovery: dWallet not Active');
	}
	const dwalletPublicOutput = Uint8Array.from(dWallet.state.Active.public_output);
	const pp = await ikaClient.getProtocolPublicParameters(dWallet);
	const { secretShare } = await params.userShareEncryptionKeys.decryptUserShare(
		dWallet,
		params.encryptedUserShare,
		pp,
	);

	// Each presign reserved on this proposal is referenced by id. Wait until
	// each Presign has reached "Completed" before pulling its presign payload.
	phase('waiting-for-presigns');
	const timeoutMs = params.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const interval = params.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
	const presignIds = proposal.proposal_presigns.map((p) => p.presign_id);
	const presigns = await Promise.all(
		presignIds.map((id) =>
			ikaClient.getPresignInParticularState(id, 'Completed', {
				timeout: timeoutMs,
				interval,
			}),
		),
	);

	phase('building-signatures');
	const msgCentralizedSigs: Uint8Array[] = [];
	for (let i = 0; i < n; i++) {
		const sig = await createUserSignMessageWithPublicOutput(
			pp,
			dwalletPublicOutput,
			secretShare,
			Uint8Array.from(presigns[i]!.state.Completed.presign),
			sweepMessages[i]!,
			Hash.SHA512,
			SignatureAlgorithm.EdDSA,
			Curve.ED25519,
		);
		msgCentralizedSigs.push(sig);
	}

	// Build executor credential.
	phase('auth-ceremony');
	const challenge = buildExecuteChallenge(client.ref.recoveryId, params.proposalId);
	const credentialInput = await params.authSigner.sign(challenge);

	const tx = new Transaction();
	const ikaFee = (params.ikaFeePerMessage ?? DEFAULT_IKA_FEE) * BigInt(n);
	const suiFee = (params.suiFeePerMessage ?? DEFAULT_SUI_FEE) * BigInt(n);
	const ikaCoin = coinWithBalance({
		balance: ikaFee,
		type: client.ikaCoinType,
	});
	const suiCoin = coinWithBalance({ balance: suiFee });
	const credArg = buildCredential(tx, client.ref.packageId, credentialInput);
	const sweepArg = tx.pure(
		bcs.vector(bcs.vector(bcs.u8())).serialize(sweepMessages.map((m) => Array.from(m))),
	);
	const sigsArg = tx.pure(
		bcs.vector(bcs.vector(bcs.u8())).serialize(msgCentralizedSigs.map((s) => Array.from(s))),
	);

	tx.add(
		moveRecovery.execute({
			package: client.ref.packageId,
			arguments: [
				client.ref.recoveryId,
				ikaClient.ikaConfig.objects.ikaDWalletCoordinator.objectID,
				params.proposalId,
				sweepArg,
				sigsArg,
				credArg,
				ikaCoin,
				suiCoin,
			],
		}),
	);
	tx.transferObjects([ikaCoin, suiCoin], executor.address);

	phase('submitting-execute');
	const result = await executor.signAndExecute(tx);
	if (result.$kind !== 'Transaction') {
		throw new Error(`executeRecovery: failed: ${JSON.stringify(result.FailedTransaction.status)}`);
	}

	const signEvents = result.Transaction.events.filter((e) =>
		e.eventType.includes('SignRequestEvent'),
	);
	if (signEvents.length !== n) {
		throw new Error(`executeRecovery: expected ${n} SignRequestEvent(s), got ${signEvents.length}`);
	}
	const signIds = signEvents.map((e) => {
		if (!e.bcs) throw new Error('executeRecovery: SignRequestEvent missing bcs payload');
		const parsed = SessionsManagerModule.DWalletSessionEvent(
			CoordinatorInnerModule.SignRequestEvent,
		).parse(new Uint8Array(e.bcs));
		return parsed.event_data.sign_id;
	});

	const signedTransactions: Uint8Array[] = [];
	for (let i = 0; i < n; i++) {
		phase('waiting-for-sign-sessions', { index: i + 1, total: n });
		const sign = await ikaClient.getSignInParticularState(
			signIds[i]!,
			Curve.ED25519,
			SignatureAlgorithm.EdDSA,
			'Completed',
			{ timeout: timeoutMs, interval },
		);
		const signature = await parseSignatureFromSignOutput(
			Curve.ED25519,
			SignatureAlgorithm.EdDSA,
			Uint8Array.from(sign.state.Completed.signature),
		);
		signedTransactions.push(assembleSignedTransaction(sweepMessages[i]!, signature));
	}
	phase('assembling');

	return {
		digest: result.Transaction.digest,
		signedTransactions,
		signIds,
		sweepMessages,
	};
}

// ===== previewProposal =====

export interface ProposalSnapshot {
	proposalId: bigint;
	/** `sha256(BCS(vector<SweepIntent>))`. Stable across blockhash refreshes. */
	intentHash: Uint8Array;
	approvals: bigint;
	threshold: bigint;
	voters: Uint8Array[];
	executed: boolean;
	/** Decoded human-readable summary of what the bundle will do on Solana. */
	preview: BundlePreview;
}

/**
 * Read a proposal off-chain and return both the raw approval state AND a
 * decoded preview of the bundle. The preview is built by rebuilding fresh
 * sweep messages from the stored intents with a placeholder blockhash and
 * decoding instruction-by-instruction — purely for display.
 */
export async function previewProposal(
	client: RecoveryClient,
	proposalId: bigint,
): Promise<ProposalSnapshot> {
	const state = await readRecoveryState(client);
	const proposal = await readProposal(client, proposalId);
	const intents = proposal.sweep_intents.map(decodeStoredIntent);
	// Placeholder blockhash so the preview doesn't need a Solana RPC roundtrip.
	// 32 base58 "1"s = 32 zero bytes — the canonical valid 32-byte blockhash.
	// The decoded instruction breakdown is independent of which blockhash is
	// baked in.
	const placeholderBlockhash = '1'.repeat(32);
	let preview: BundlePreview;
	try {
		const messages = rebuildSweepFromIntents(intents, placeholderBlockhash);
		preview = previewMessageBytes(messages);
	} catch {
		preview = {
			txCount: intents.length,
			txs: [],
			totalLamportsTransferred: 0n,
			totalSplTransferred: [],
		};
	}
	return {
		proposalId,
		intentHash: Uint8Array.from(proposal.intent_hash),
		approvals: BigInt(proposal.approvals),
		threshold: state.threshold,
		voters: proposal.voters.contents.map((v) => Uint8Array.from(v)),
		executed: proposal.executed,
		preview,
	};
}

// ===== internal helpers =====

async function readProposal(client: RecoveryClient, proposalId: bigint) {
	const state = await readRecoveryState(client);
	const { dynamicField } = await client.suiClient.core.getDynamicField({
		parentId: state.proposalsTableId,
		name: { type: 'u64', bcs: bcs.u64().serialize(proposalId).toBytes() },
	});
	return moveRecovery.RecoveryProposal.parse(dynamicField.value.bcs);
}

/** Decode a BCS-deserialized `SweepIntent` into the JS shape `solana/intent` uses. */
function decodeStoredIntent(raw: {
	fee_payer: number[];
	ixs: Array<Record<string, unknown>>;
}): SweepIntent {
	return {
		fee_payer: Uint8Array.from(raw.fee_payer),
		ixs: raw.ixs.map((ix) => decodeStoredIx(ix)),
	};
}

function decodeStoredIx(raw: Record<string, unknown>): SweepIntent['ixs'][number] {
	if (raw.SystemTransfer) {
		const r = raw.SystemTransfer as {
			from: number[];
			to: number[];
			lamports: string | number | bigint;
		};
		return {
			SystemTransfer: {
				from: Uint8Array.from(r.from),
				to: Uint8Array.from(r.to),
				lamports: BigInt(r.lamports),
			},
		};
	}
	if (raw.SplTransferChecked) {
		const r = raw.SplTransferChecked as {
			program_id: number[];
			source: number[];
			mint: number[];
			destination: number[];
			authority: number[];
			amount: string | number | bigint;
			decimals: number;
		};
		return {
			SplTransferChecked: {
				program_id: Uint8Array.from(r.program_id),
				source: Uint8Array.from(r.source),
				mint: Uint8Array.from(r.mint),
				destination: Uint8Array.from(r.destination),
				authority: Uint8Array.from(r.authority),
				amount: BigInt(r.amount),
				decimals: r.decimals,
			},
		};
	}
	if (raw.AtaCreateIdempotent) {
		const r = raw.AtaCreateIdempotent as {
			token_program: number[];
			payer: number[];
			ata: number[];
			owner: number[];
			mint: number[];
		};
		return {
			AtaCreateIdempotent: {
				token_program: Uint8Array.from(r.token_program),
				payer: Uint8Array.from(r.payer),
				ata: Uint8Array.from(r.ata),
				owner: Uint8Array.from(r.owner),
				mint: Uint8Array.from(r.mint),
			},
		};
	}
	if (raw.SplCloseAccount) {
		const r = raw.SplCloseAccount as {
			program_id: number[];
			account: number[];
			destination: number[];
			authority: number[];
		};
		return {
			SplCloseAccount: {
				program_id: Uint8Array.from(r.program_id),
				account: Uint8Array.from(r.account),
				destination: Uint8Array.from(r.destination),
				authority: Uint8Array.from(r.authority),
			},
		};
	}
	throw new Error('decodeStoredIx: unknown variant');
}

function byteEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}
