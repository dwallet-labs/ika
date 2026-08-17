'use client';

import { Button, Card, cn, Skeleton, SkeletonLine } from '@fesal-packages/ikavery-frontend-ui';
import { previewProposal, type ProposalSnapshot } from '@fesal-packages/ikavery-sui-sdk';
import { useWalletConnection, useWallets } from '@mysten/dapp-kit-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
	ArrowLeft,
	CheckCircle2,
	ExternalLink,
	Loader2,
	RefreshCw,
	Send,
	ShieldCheck,
	Signature,
	XCircle,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { ErrorShell } from '@/components/vault/error-shell';
import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { resolveCredentialRequest, signerOptionToIdentity } from '@/lib/credential-bridge';
import { dAppKit } from '@/lib/dapp-kit';
import { findMyEncryptedShareId } from '@/lib/encrypted-share-discovery';
import { env } from '@/lib/env';
import { bytesToHex } from '@/lib/format';
import { ESTIMATE_APPROVE, estimateExecute } from '@/lib/gas-preflight';
import { buildRecoveryClient } from '@/lib/recovery-client';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import { bytesEq, explorerObjectUrl } from '@/lib/recovery-state';
import { buildSignAndExecute } from '@/lib/sponsored-sign';
import {
	appendSavedVault,
	hexToBytes,
	loadActiveImporter,
	loadSavedVaults,
	type CachedImporter,
	type SavedVault,
} from '@/lib/storage';
import { useVaultQuery } from '@/lib/use-vault';

interface BroadcastEntry {
	txIndex: number;
	signature: string | null;
	error?: string;
	/** Set while a per-row retry is in flight. */
	retrying?: boolean;
}

export default function ProposalPage() {
	const router = useRouter();
	const params = useParams<{ recoveryId: string; id: string }>();
	const recoveryId = params.recoveryId;
	const proposalIdStr = params.id;
	const { suiClient, session } = useRecoveryClient();
	const walletSign = dAppKit.signTransaction;
	const wallets = useWallets();
	const { wallet: currentWallet } = useWalletConnection();
	const queryClient = useQueryClient();

	const proposalId = React.useMemo(() => {
		try {
			return BigInt(proposalIdStr);
		} catch {
			return null;
		}
	}, [proposalIdStr]);

	const vault = useVaultQuery(recoveryId);

	const snapshot = useQuery({
		queryKey: ['proposal', recoveryId, proposalIdStr, suiClient ? 'ready' : '_'],
		enabled: !!suiClient && !!recoveryId && proposalId !== null,
		queryFn: async (): Promise<ProposalSnapshot> => {
			// No initialize() — previewProposal is BCS-only, no WASM needed.
			const recClient = buildRecoveryClient(suiClient!, recoveryId);
			return previewProposal(recClient, proposalId!);
		},
		refetchInterval: 4000,
		staleTime: 2000,
	});

	const signerState = useSignerState(vault.data);

	// Load this device's importer + saved share id. Both are needed at execute
	// time: the share id selects WHICH encrypted share we decrypt, and the
	// importer key bytes are the decryption key.
	const [cachedImporter, setCachedImporter] = React.useState<CachedImporter | null>(null);
	const [savedVault, setSavedVault] = React.useState<SavedVault | null>(null);
	React.useEffect(() => {
		void (async () => {
			setCachedImporter(await loadActiveImporter());
			const vaults = await loadSavedVaults();
			setSavedVault(vaults.find((v) => v.recoveryId === recoveryId) ?? null);
		})();
	}, [recoveryId]);

	// Backfill share id on-chain if it's not in local storage. Walks the
	// dWallet's `encrypted_user_secret_key_shares` table to find the entry
	// keyed to this device's encryption address.
	React.useEffect(() => {
		if (!suiClient || !vault.data || !cachedImporter) return;
		if (savedVault?.myEncryptedUserShareId) return;
		let cancelled = false;
		void (async () => {
			try {
				const found = await findMyEncryptedShareId(
					suiClient,
					vault.data.dwalletId,
					cachedImporter.encryptionAddress,
				);
				if (cancelled || !found) return;
				const next: SavedVault = savedVault
					? { ...savedVault, myEncryptedUserShareId: found }
					: {
							recoveryId,
							dwalletId: vault.data.dwalletId,
							threshold: vault.data.threshold,
							totalMembers: vault.data.members.length,
							createdAt: Date.now(),
							myEncryptedUserShareId: found,
						};
				await appendSavedVault(next);
				setSavedVault(next);
			} catch {
				// Best-effort; the user can still execute manually if we surface a
				// good error from the SDK.
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [suiClient, vault.data, cachedImporter, savedVault, recoveryId]);

	// Active signer's canonical member id `[scheme, ...pubkey]` — used to
	// detect whether they've already voted on this proposal.
	const myMemberId = React.useMemo<Uint8Array | null>(() => {
		const active = signerState.state.active;
		if (!active) return null;
		return active.member.id;
	}, [signerState.state.active]);

	const alreadyVoted = React.useMemo(() => {
		if (!myMemberId || !snapshot.data) return false;
		return snapshot.data.voters.some((v) => bytesEq(v, myMemberId));
	}, [myMemberId, snapshot.data]);

	// Bundle preview that survives execute: chain drains `sweep_messages` from
	// the proposal once executed, so a post-execute snapshot decodes to 0/0/0.
	// We sticky the last non-empty preview here so the user keeps seeing the
	// numbers they signed, instead of a confusing all-zero card.
	const stickyBundleRef = React.useRef<{
		txCount: number;
		totalLamports: bigint;
		totalSpl: number;
		txs: {
			messageByteLength: number;
			actions: Array<
				| { kind: 'sol'; amount: bigint }
				| { kind: 'spl'; mint: string; amount: bigint; decimals: number }
			>;
		}[];
	} | null>(null);
	const bundleView = React.useMemo(() => {
		if (snapshot.data && snapshot.data.preview.txCount > 0) {
			stickyBundleRef.current = {
				txCount: snapshot.data.preview.txCount,
				totalLamports: snapshot.data.preview.totalLamportsTransferred,
				totalSpl: snapshot.data.preview.totalSplTransferred.length,
				txs: snapshot.data.preview.txs.map((t) => ({
					messageByteLength: t.messageByteLength,
					actions: instructionsToActions(t.instructions),
				})),
			};
		}
		return stickyBundleRef.current;
	}, [snapshot.data]);

	const [actionState, setActionState] = React.useState<
		| { stage: 'idle' }
		| { stage: 'approving' }
		| { stage: 'executing'; phaseLabel?: string }
		| { stage: 'broadcasting'; signedCount: number }
		| {
				stage: 'broadcasted';
				results: BroadcastEntry[];
				suiDigest: string;
				/** Kept around so failed rows can be retried in place. */
				signedTransactions: Uint8Array[];
		  }
		| { stage: 'error'; message: string }
	>({ stage: 'idle' });

	async function handleApprove() {
		if (!session || !suiClient || !vault.data || !snapshot.data) return;
		const active = signerState.state.active;
		const gasPayer = signerState.state.gasPayer;
		if (!active || !gasPayer) {
			setActionState({
				stage: 'error',
				message: 'Pick a signer and connect a wallet first.',
			});
			return;
		}
		setActionState({ stage: 'approving' });
		try {
			const signAndExecute = buildSignAndExecute({
				gasPayer,
				currentWallet: currentWallet ?? null,
				walletSign: async ({ transaction }) => await walletSign({ transaction }),
				suiClient,
				network: env.network,
			});
			await session.runApproveRecovery({
				walletAddress: gasPayer.address,
				signAndExecute,
				resolveCredential: (challenge, identity) =>
					resolveCredentialRequest(challenge, identity, { wallets }),
				recoveryId,
				proposalId: proposalIdStr,
				authIdentity: signerOptionToIdentity(active),
			});
			setActionState({ stage: 'idle' });
			await queryClient.invalidateQueries({
				queryKey: ['proposal', recoveryId, proposalIdStr],
			});
			await queryClient.invalidateQueries({ queryKey: ['vault', recoveryId] });
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setActionState({ stage: 'error', message });
		}
	}

	async function handleExecute() {
		if (!session || !suiClient || !vault.data || !snapshot.data) return;
		const active = signerState.state.active;
		const gasPayer = signerState.state.gasPayer;
		if (!active || !gasPayer) {
			setActionState({
				stage: 'error',
				message: 'Pick a signer and connect a wallet first.',
			});
			return;
		}
		if (active.kind === 'approver') {
			setActionState({
				stage: 'error',
				message:
					"Approver-only members can vote but can't execute — they don't hold an encrypted share. Switch to a key-holder member (passkey or wallet enrolled with a stable signing key).",
			});
			return;
		}
		if (!cachedImporter) {
			setActionState({
				stage: 'error',
				message:
					'No encryption identity cached on this device. Re-run setup or enroll on this device first — execute needs to decrypt the user share.',
			});
			return;
		}
		if (!savedVault?.myEncryptedUserShareId) {
			setActionState({
				stage: 'error',
				message:
					"This device's encrypted share id couldn't be located. Wait for the background lookup to finish, or run setup/enrollment on this device.",
			});
			return;
		}
		setActionState({ stage: 'executing' });
		try {
			const signAndExecute = buildSignAndExecute({
				gasPayer,
				currentWallet: currentWallet ?? null,
				walletSign: async ({ transaction }) => await walletSign({ transaction }),
				suiClient,
				network: env.network,
			});
			const result = await session.runExecuteRecovery({
				walletAddress: gasPayer.address,
				signAndExecute,
				resolveCredential: (challenge, identity) =>
					resolveCredentialRequest(challenge, identity, { wallets }),
				recoveryId,
				proposalId: proposalIdStr,
				importerKeyBytes: hexToBytes(cachedImporter.encryptionKeysBytesHex),
				encryptedUserShareId: savedVault.myEncryptedUserShareId,
				solanaRpcUrl: env.solanaRpc,
				authIdentity: signerOptionToIdentity(active),
				onProgress: ({ phase, index, total }) => {
					setActionState({
						stage: 'executing',
						phaseLabel: executePhaseLabel(phase, index, total),
					});
				},
			});

			setActionState({
				stage: 'broadcasting',
				signedCount: result.signedTransactions.length,
			});

			// Broadcast to Solana on the main thread — uses @solana/web3.js
			// (lazy-imported so it doesn't bloat the proposal-page bundle on idle).
			const { Connection } = await import('@solana/web3.js');
			const { broadcastSignedTransactions } = await import('@fesal-packages/ikavery-core');
			const conn = new Connection(env.solanaRpc, 'confirmed');
			const broadcastResults = await broadcastSignedTransactions(conn, result.signedTransactions, {
				skipPreflight: false,
				maxRetries: 5,
			});
			const entries: BroadcastEntry[] = broadcastResults.map((r) => ({
				txIndex: r.txIndex,
				signature: r.signature,
				error: r.error ? (r.error instanceof Error ? r.error.message : String(r.error)) : undefined,
			}));

			setActionState({
				stage: 'broadcasted',
				results: entries,
				suiDigest: result.digest,
				signedTransactions: result.signedTransactions,
			});
			await queryClient.invalidateQueries({
				queryKey: ['proposal', recoveryId, proposalIdStr],
			});
			await queryClient.invalidateQueries({ queryKey: ['vault', recoveryId] });
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setActionState({ stage: 'error', message });
		}
	}

	/**
	 * Re-broadcast a single Solana tx whose first attempt failed. The
	 * signed bytes already commit to a recent blockhash captured at execute
	 * time — retries within ~60s usually land. Beyond that the user has to
	 * re-propose so a fresh blockhash gets baked in.
	 */
	async function handleRetryBroadcast(txIndex: number) {
		setActionState((s) => {
			if (s.stage !== 'broadcasted') return s;
			return {
				...s,
				results: s.results.map((r) =>
					r.txIndex === txIndex ? { ...r, retrying: true, error: undefined } : r,
				),
			};
		});
		try {
			const snap = actionState.stage === 'broadcasted' ? actionState : null;
			if (!snap) return;
			const signed = snap.signedTransactions[txIndex];
			if (!signed) {
				throw new Error(`No signed bytes for tx #${txIndex + 1}`);
			}
			const { Connection } = await import('@solana/web3.js');
			const conn = new Connection(env.solanaRpc, 'confirmed');
			const sig = await conn.sendRawTransaction(signed, {
				skipPreflight: false,
				maxRetries: 5,
			});
			setActionState((s) => {
				if (s.stage !== 'broadcasted') return s;
				return {
					...s,
					results: s.results.map((r) =>
						r.txIndex === txIndex ? { txIndex, signature: sig, retrying: false } : r,
					),
				};
			});
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setActionState((s) => {
				if (s.stage !== 'broadcasted') return s;
				return {
					...s,
					results: s.results.map((r) =>
						r.txIndex === txIndex
							? { txIndex, signature: null, error: message, retrying: false }
							: r,
					),
				};
			});
		}
	}

	if (proposalId === null) {
		return (
			<ErrorShell
				recoveryId={recoveryId}
				title="Couldn't open this proposal."
				message={`"${proposalIdStr}" is not a valid proposal id.`}
			/>
		);
	}
	if (vault.error || snapshot.error) {
		const msg = vault.error
			? vault.error instanceof Error
				? vault.error.message
				: String(vault.error)
			: snapshot.error instanceof Error
				? snapshot.error.message
				: String(snapshot.error);
		return (
			<ErrorShell recoveryId={recoveryId} title="Couldn't open this proposal." message={msg} />
		);
	}
	if (!vault.data || !snapshot.data) {
		return <ProposalSkeleton recoveryId={recoveryId} idStr={proposalIdStr} />;
	}

	const snap = snapshot.data;
	const approvalsNum = Number(snap.approvals);
	const thresholdNum = Number(snap.threshold);
	const ratio = thresholdNum === 0 ? 1 : Math.min(1, approvalsNum / thresholdNum);
	const reachedThreshold = approvalsNum >= thresholdNum;

	return (
		<>
			<button
				onClick={() => router.push(`/vault/${recoveryId}`)}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-8"
			>
				<ArrowLeft className="h-3 w-3" />
				Back to vault
			</button>

			<header className="mb-8">
				<span className="smallcaps text-clay">Recovery proposal</span>
				<h1 className="mt-3 font-display text-[40px] sm:text-[56px] lg:text-[72px] leading-[0.98] tracking-[-0.025em] text-text">
					#{proposalIdStr}
				</h1>
				<p className="mt-4 max-w-[640px] text-[15px] text-text-2 leading-[1.6]">
					One signature per Solana transaction in the bundle. The dWallet signs once a quorum of{' '}
					{thresholdNum} approval
					{thresholdNum === 1 ? '' : 's'} is collected.
				</p>
			</header>

			<div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
				{/* Approvals meter */}
				<Card tone="raised" className="lg:col-span-7 p-0 overflow-hidden">
					<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-3">Approvals</span>
						<span
							className={cn(
								'smallcaps inline-flex items-center gap-1.5',
								snap.executed ? 'text-text-3' : reachedThreshold ? 'text-sage' : 'text-clay',
							)}
						>
							{snap.executed ? (
								<>
									<ShieldCheck className="h-3 w-3" />
									Executed
								</>
							) : reachedThreshold ? (
								<>
									<CheckCircle2 className="h-3 w-3" />
									Quorum reached
								</>
							) : (
								<>
									<Signature className="h-3 w-3" />
									Awaiting signatures
								</>
							)}
						</span>
					</div>
					<div className="px-5 sm:px-8 py-6 sm:py-7 flex items-baseline gap-2 sm:gap-3">
						<span
							className={cn(
								'font-display text-[52px] sm:text-[80px] leading-[0.9] tabular',
								reachedThreshold ? 'text-sage' : 'text-text',
							)}
						>
							{approvalsNum}
						</span>
						<span className="font-display italic text-text-3 text-[20px] sm:text-[26px] tracking-tight">
							of
						</span>
						<span className="font-display text-[52px] sm:text-[80px] leading-[0.9] tabular text-text-2">
							{thresholdNum}
						</span>
					</div>
					<div className="px-5 sm:px-8 pb-6">
						<div className="h-1.5 w-full bg-surface-3 rounded overflow-hidden">
							<div
								className={cn(
									'h-full transition-all duration-500',
									reachedThreshold ? 'bg-sage' : 'bg-clay',
								)}
								style={{ width: `${ratio * 100}%` }}
							/>
						</div>
					</div>
					{/* Voters */}
					<div className="px-5 sm:px-8 py-3 border-t border-border">
						<span className="smallcaps text-text-3">Voted</span>
					</div>
					<ul className="divide-y divide-border">
						{snap.voters.length === 0 && (
							<li className="px-5 sm:px-8 py-4 text-[13px] text-text-3">No approvals yet.</li>
						)}
						{snap.voters.map((v, i) => (
							<li
								key={i}
								className="px-5 sm:px-8 py-3 font-mono text-[12px] tabular text-text-2 break-all"
							>
								{voterLabel(v)} · {bytesToHex(v)}
							</li>
						))}
					</ul>
				</Card>

				{/* Bundle preview */}
				<Card tone="raised" className="lg:col-span-5 p-0 overflow-hidden">
					<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-3">Bundle</span>
						<span className="font-mono text-[10.5px] tabular text-text-4 break-all">
							{bytesToHex(snap.intentHash).slice(0, 12)}…
						</span>
					</div>
					{bundleView ? (
						<>
							<div className="divide-y divide-border">
								<Stat
									label="Transactions"
									value={`${bundleView.txCount}`}
									hint="One presign per tx at execute time."
								/>
								<Stat
									label="SOL transferred"
									value={`${(Number(bundleView.totalLamports) / 1e9).toFixed(6)} SOL`}
								/>
								{bundleView.totalSpl > 0 && (
									<Stat label="SPL transfers" value={`${bundleView.totalSpl}`} />
								)}
							</div>
							<div className="px-5 sm:px-8 py-4 border-t border-border">
								<span className="smallcaps text-text-3">Per-tx breakdown</span>
								<ol className="mt-3 space-y-3.5">
									{bundleView.txs.map((t, i) => (
										<li key={i} className="flex items-baseline gap-3">
											<span className="font-mono text-[10.5px] text-text-4 tabular w-6 pt-0.5">
												{String(i + 1).padStart(2, '0')}
											</span>
											<ul className="flex-1 space-y-1">
												{t.actions.length === 0 ? (
													<li className="text-[12.5px] text-text-4 italic">
														(chrome only — no transfers)
													</li>
												) : (
													t.actions.map((a, j) =>
														a.kind === 'sol' ? (
															<li key={j} className="text-[13px] text-text-2 leading-[1.5]">
																Sweep{' '}
																<span className="font-mono tabular text-text">
																	{(Number(a.amount) / 1e9).toFixed(6)}
																</span>{' '}
																<span className="text-text-3">SOL</span>
															</li>
														) : (
															<li key={j} className="text-[13px] text-text-2 leading-[1.5]">
																Sweep{' '}
																<span className="font-mono tabular text-text">
																	{formatSplAmount(a.amount, a.decimals)}
																</span>{' '}
																<span className="text-text-3">of</span>{' '}
																<span className="font-mono text-[11.5px] text-text" title={a.mint}>
																	{shortMint(a.mint)}
																</span>
															</li>
														),
													)
												)}
											</ul>
											<span className="font-mono text-[10.5px] text-text-4 tabular pt-0.5">
												{t.messageByteLength}B
											</span>
										</li>
									))}
								</ol>
							</div>
						</>
					) : (
						<div className="px-5 sm:px-8 py-8 flex items-start gap-3">
							<ShieldCheck className="h-4 w-4 text-text-3 mt-0.5 flex-none" />
							<div className="text-[13px] text-text-2 leading-[1.55]">
								<div className="smallcaps text-text-3 mb-1">No bundle</div>
								Intents for this proposal couldn&apos;t be decoded for preview. The intent hash
								above is the canonical identifier.
							</div>
						</div>
					)}
				</Card>
			</div>

			{/* Signer + gas-payer */}
			{!snap.executed && (
				<div className="mt-4">
					<SignerGasPayerCard
						vault={vault.data}
						state={signerState.state}
						onPickSigner={signerState.pickSigner}
						onPickGas={signerState.pickGas}
						estimate={
							// Once approved, the next action this card guards is Execute —
							// size the budget against the larger demand. Approver-only
							// signers can never execute, so they get the lighter approve
							// estimate.
							signerState.state.active?.kind === 'approver'
								? ESTIMATE_APPROVE
								: reachedThreshold
									? estimateExecute(snap.preview.txs.length)
									: ESTIMATE_APPROVE
						}
					/>
				</div>
			)}

			{/* Action footer */}
			{!snap.executed && (
				<div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-end gap-3">
					{actionState.stage === 'error' && (
						<p className="flex-1 text-[12.5px] text-clay leading-[1.5]">{actionState.message}</p>
					)}
					{actionState.stage !== 'error' && signerState.state.active?.kind === 'approver' && (
						<p className="flex-1 text-[12.5px] text-text-3 leading-[1.5]">
							Approver-only signer — you can approve, but executing requires a key-holder member.
						</p>
					)}
					<Button
						variant="secondary"
						size="lg"
						disabled={
							!myMemberId ||
							!signerState.state.ready ||
							alreadyVoted ||
							snap.executed ||
							actionState.stage === 'approving' ||
							actionState.stage === 'executing' ||
							actionState.stage === 'broadcasting'
						}
						onClick={handleApprove}
					>
						{actionState.stage === 'approving' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Approving…
							</>
						) : (
							<>
								<Signature className="h-4 w-4" />
								{alreadyVoted ? 'You approved' : 'Approve'}
							</>
						)}
					</Button>
					<Button
						variant="irreversible"
						size="lg"
						disabled={
							!reachedThreshold ||
							snap.executed ||
							!signerState.state.gasPayer ||
							signerState.state.active?.kind === 'approver' ||
							!cachedImporter ||
							!savedVault?.myEncryptedUserShareId ||
							actionState.stage === 'executing' ||
							actionState.stage === 'broadcasting' ||
							actionState.stage === 'approving'
						}
						onClick={handleExecute}
					>
						{actionState.stage === 'executing' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								{actionState.phaseLabel ?? 'Executing…'}
							</>
						) : actionState.stage === 'broadcasting' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Broadcasting {actionState.signedCount} tx…
							</>
						) : (
							<>
								<Send className="h-4 w-4" />
								Execute &amp; broadcast
							</>
						)}
					</Button>
				</div>
			)}

			{actionState.stage === 'broadcasted' && (
				<Card tone="raised" className="mt-6 p-0 overflow-hidden border-sage/40">
					<div className="px-6 py-4 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-sage inline-flex items-center gap-1.5">
							<CheckCircle2 className="h-3.5 w-3.5" />
							Broadcast results
						</span>
						<a
							href={explorerObjectUrl(actionState.suiDigest)}
							target="_blank"
							rel="noopener noreferrer"
							className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1"
						>
							<ExternalLink className="h-3 w-3" />
							Sui explorer
						</a>
					</div>
					<ul className="divide-y divide-border">
						{actionState.results.map((r) => (
							<li key={r.txIndex} className="px-6 py-3 flex items-center gap-3 text-[13px]">
								<span className="font-mono text-[10.5px] text-text-4 tabular w-8 flex-none">
									#{String(r.txIndex + 1).padStart(2, '0')}
								</span>
								{r.signature ? (
									<>
										<CheckCircle2 className="h-3.5 w-3.5 text-sage flex-none" />
										<a
											href={solanaExplorerTx(r.signature)}
											target="_blank"
											rel="noopener noreferrer"
											className="flex-1 font-mono text-[12px] tabular text-text break-all hover:text-clay"
										>
											{r.signature}
										</a>
									</>
								) : r.retrying ? (
									<>
										<Loader2 className="h-3.5 w-3.5 text-clay flex-none animate-spin" />
										<span className="flex-1 text-text-3 text-[12.5px] leading-[1.5]">
											Re-broadcasting…
										</span>
									</>
								) : (
									<>
										<XCircle className="h-3.5 w-3.5 text-clay flex-none" />
										<span className="flex-1 text-clay text-[12.5px] leading-[1.5] break-all">
											{r.error ?? 'Failed'}
										</span>
										<Button
											variant="ghost"
											size="sm"
											onClick={() => void handleRetryBroadcast(r.txIndex)}
										>
											<RefreshCw className="h-3.5 w-3.5" />
											Retry
										</Button>
									</>
								)}
							</li>
						))}
					</ul>
					{actionState.results.some((r) => !r.signature && !r.retrying) && (
						<div className="px-6 py-4 border-t border-border flex flex-col gap-3">
							<p className="text-[12.5px] text-text-3 leading-[1.5]">
								The signed transactions reference a Solana blockhash captured during execute.
								Retries that land within ~60s usually succeed; beyond that the blockhash will have
								expired and you&apos;ll need to re-propose so a fresh blockhash gets baked into new
								messages.
							</p>
							<div className="flex items-center gap-3">
								<Button
									variant="secondary"
									size="default"
									onClick={() => {
										if (actionState.stage !== 'broadcasted') return;
										for (const r of actionState.results) {
											if (!r.signature && !r.retrying) {
												void handleRetryBroadcast(r.txIndex);
											}
										}
									}}
								>
									<RefreshCw className="h-3.5 w-3.5" />
									Retry all failed
								</Button>
								<Button
									variant="ghost"
									size="default"
									onClick={() => router.push(`/vault/${recoveryId}/recover`)}
								>
									Re-propose with fresh blockhash
								</Button>
							</div>
						</div>
					)}
				</Card>
			)}
		</>
	);
}

function ProposalSkeleton({ recoveryId, idStr }: { recoveryId: string; idStr: string }) {
	const router = useRouter();
	return (
		<>
			<button
				type="button"
				onClick={() => router.push(`/vault/${recoveryId}`)}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-8"
			>
				<ArrowLeft className="h-3 w-3" />
				Back to vault
			</button>
			<header className="mb-8">
				<span className="smallcaps text-clay">Recovery proposal</span>
				<h1 className="mt-3 font-display text-[40px] sm:text-[56px] lg:text-[72px] leading-[0.98] tracking-[-0.025em] text-text">
					#{idStr}
				</h1>
				<SkeletonLine className="mt-4 h-3.5 w-full max-w-[480px]" />
			</header>
			<div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
				<Card tone="raised" className="lg:col-span-7 p-0 overflow-hidden">
					<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-3">Approvals</span>
						<SkeletonLine className="w-20" />
					</div>
					<div className="px-5 sm:px-8 py-6 sm:py-7 flex items-baseline gap-3">
						<Skeleton className="h-[52px] sm:h-[80px] w-16 sm:w-24" />
						<span className="font-display italic text-text-3 text-[20px] sm:text-[26px] tracking-tight">
							of
						</span>
						<Skeleton className="h-[52px] sm:h-[80px] w-16 sm:w-24" />
					</div>
					<div className="px-5 sm:px-8 pb-6">
						<Skeleton className="h-1.5 w-full" />
					</div>
					<div className="px-5 sm:px-8 py-4 border-t border-border space-y-3">
						<SkeletonLine className="w-2/3" />
						<SkeletonLine className="w-1/2" />
					</div>
				</Card>
				<Card tone="raised" className="lg:col-span-5 p-0 overflow-hidden">
					<div className="px-5 sm:px-8 py-3 border-b border-border">
						<span className="smallcaps text-text-3">Sweep bundle</span>
					</div>
					<div className="px-5 sm:px-8 py-5 space-y-4">
						<SkeletonLine className="w-1/2 h-4" />
						<Skeleton className="h-16 w-full" />
						<Skeleton className="h-16 w-full" />
					</div>
				</Card>
			</div>
		</>
	);
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
	return (
		<div className="px-5 sm:px-8 py-4 flex items-baseline justify-between gap-3">
			<div>
				<div className="smallcaps text-text-3">{label}</div>
				{hint && <div className="smallcaps text-text-4 mt-0.5">{hint}</div>}
			</div>
			<span className="font-mono text-[18px] tabular text-text">{value}</span>
		</div>
	);
}

function voterLabel(id: Uint8Array): string {
	if (id.length === 0) return '?';
	switch (id[0]) {
		case 0:
			return 'Ed25519';
		case 1:
			return 'Secp256k1';
		case 2:
			return 'Secp256r1';
		case 3:
			return 'Passkey';
		case 4:
			return 'Approver';
		default:
			return '?';
	}
}

function executePhaseLabel(
	phase: import('@/lib/session').ExecutePhase,
	index?: number,
	total?: number,
): string {
	switch (phase) {
		case 'reading-proposal':
			return 'Reading proposal…';
		case 'fetching-blockhash':
			return 'Fetching Solana blockhash…';
		case 'decrypting-share':
			return 'Decrypting your share…';
		case 'waiting-for-presigns':
			return 'Waiting for presigns…';
		case 'building-signatures':
			return 'Building signatures…';
		case 'auth-ceremony':
			return 'Awaiting auth signature…';
		case 'submitting-execute':
			return 'Submitting execute tx…';
		case 'waiting-for-sign-sessions':
			return total != null && index != null
				? `Waiting for IKA signature ${index}/${total}…`
				: 'Waiting for IKA signatures…';
		case 'assembling':
			return 'Assembling Solana txs…';
	}
}

function instructionsToActions(
	instructions: ProposalSnapshot['preview']['txs'][number]['instructions'],
): Array<
	{ kind: 'sol'; amount: bigint } | { kind: 'spl'; mint: string; amount: bigint; decimals: number }
> {
	const actions: Array<
		| { kind: 'sol'; amount: bigint }
		| { kind: 'spl'; mint: string; amount: bigint; decimals: number }
	> = [];
	for (const ix of instructions) {
		if (ix.kind === 'system-transfer') {
			actions.push({ kind: 'sol', amount: ix.lamports });
		} else if (ix.kind === 'spl-transfer-checked') {
			actions.push({
				kind: 'spl',
				mint: ix.mint,
				amount: ix.amount,
				decimals: ix.decimals,
			});
		}
	}
	return actions;
}

function shortMint(mint: string): string {
	return mint.length <= 12 ? mint : `${mint.slice(0, 6)}…${mint.slice(-4)}`;
}

function formatSplAmount(amount: bigint, decimals: number): string {
	if (decimals === 0) return amount.toString();
	const base = 10n ** BigInt(decimals);
	const whole = amount / base;
	const frac = amount % base;
	const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '');
	return fracStr.length === 0 ? whole.toString() : `${whole}.${fracStr}`;
}

function solanaExplorerTx(sig: string): string {
	// env.solanaRpc is the source of truth — derive cluster suffix from it.
	const cluster = env.solanaRpc.includes('devnet')
		? '?cluster=devnet'
		: env.solanaRpc.includes('testnet')
			? '?cluster=testnet'
			: '';
	return `https://explorer.solana.com/tx/${sig}${cluster}`;
}
