'use client';

import { Button, Card, cn, Skeleton, SkeletonLine } from '@fesal-packages/ikavery-frontend-ui';
import {
	approvalPda,
	memberIdHash,
	STATUS_APPROVED,
	STATUS_EXECUTED,
} from '@fesal-packages/ikavery-solana-sdk';
import { Connection, type PublicKey } from '@solana/web3.js';
import { useQueryClient } from '@tanstack/react-query';
import {
	AlertCircle,
	CheckCircle2,
	ExternalLink,
	Loader2,
	Send,
	ShieldCheck,
	Signature,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { BackToVaultLink } from '@/components/vault/back-to-vault';
import { ErrorShell } from '@/components/vault/error-shell';
import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { SOLANA_RPC } from '@/lib/env';
import {
	approveAsMember,
	executeAndBroadcast,
	rebuildBundleMessages,
	type BroadcastResult,
	type RecoverPhase,
} from '@/lib/recover';
import { loadDkgBundle, loadSweepBundle, type DkgBundle, type SweepBundle } from '@/lib/storage';
import { useProposalQuery } from '@/lib/use-proposal';
import { useVaultQuery, type VaultState } from '@/lib/use-vault';
import { memberSlotForVoter } from '@/lib/voter';

export default function ProposalPage() {
	const params = useParams<{ recoveryId: string; id: string }>();
	const recoveryId = params.recoveryId;
	const proposalIdStr = params.id;
	const proposalIndex = Number.parseInt(proposalIdStr, 10);

	const vault = useVaultQuery(recoveryId);
	const proposal = useProposalQuery(
		vault.data?.recovery ?? null,
		Number.isFinite(proposalIndex) ? proposalIndex : null,
	);

	const [bundle, setBundle] = React.useState<DkgBundle | null | 'pending'>('pending');
	React.useEffect(() => {
		let cancelled = false;
		loadDkgBundle(recoveryId).then((b) => {
			if (!cancelled) setBundle(b);
		});
		return () => {
			cancelled = true;
		};
	}, [recoveryId]);

	if (!Number.isFinite(proposalIndex)) {
		return (
			<ErrorShell
				recoveryId={recoveryId}
				title="Couldn't open this proposal."
				message={`"${proposalIdStr}" is not a valid proposal id.`}
			/>
		);
	}
	if (vault.error || proposal.error) {
		const err = vault.error ?? proposal.error;
		return (
			<ErrorShell
				recoveryId={recoveryId}
				title="Couldn't open this proposal."
				message={err instanceof Error ? err.message : String(err)}
			/>
		);
	}
	if (vault.isLoading || proposal.isLoading || bundle === 'pending') {
		return <ProposalSkeleton recoveryId={recoveryId} idStr={proposalIdStr} />;
	}
	if (!vault.data) {
		return <ProposalSkeleton recoveryId={recoveryId} idStr={proposalIdStr} />;
	}
	if (!proposal.data?.account) {
		return (
			<ErrorShell
				recoveryId={recoveryId}
				title="Proposal not found."
				message={`Proposal #${proposalIdStr} doesn't exist on this vault. It may have been replaced by a newer one.`}
			/>
		);
	}

	return (
		<ProposalView
			recoveryId={recoveryId}
			proposalIdStr={proposalIdStr}
			proposalIndex={proposalIndex}
			vault={vault.data}
			proposalAddress={proposal.data.proposal}
			account={proposal.data.account}
			bundle={bundle}
		/>
	);
}

interface ProposalViewProps {
	recoveryId: string;
	proposalIdStr: string;
	proposalIndex: number;
	vault: VaultState;
	proposalAddress: PublicKey;
	account: NonNullable<NonNullable<ReturnType<typeof useProposalQuery>['data']>['account']>;
	bundle: DkgBundle | null;
}

function ProposalView({
	recoveryId,
	proposalIdStr,
	proposalIndex,
	vault,
	proposalAddress,
	account,
	bundle,
}: ProposalViewProps) {
	const router = useRouter();
	const queryClient = useQueryClient();
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);

	const signer = useSignerState({ members: vault.account.members });
	const voter = signer.voterFromActive();
	const gasPayer = signer.state.gasPayer;
	const meSlot = React.useMemo(() => (voter ? memberSlotForVoter(voter) : null), [voter]);

	// Voter discovery: walk the on-chain roster and check whether each
	// member's approval PDA exists. Solana doesn't store a `voters` vector
	// on the proposal; it stores a counter and writes per-member approval
	// accounts, so this is the closest analog to Sui's `voters` list.
	const [voters, setVoters] = React.useState<Uint8Array[]>([]);
	// useVaultQuery hands back a freshly-decoded members array on every 8s
	// poll, so depending on its identity directly would refire this effect
	// every poll. Stash the latest members in a ref and re-key the effect on
	// the bytes hash; only an actual roster mutation triggers a refetch.
	const membersRef = React.useRef(vault.account.members);
	membersRef.current = vault.account.members;
	const membersKey = vault.account.members.map(bytesToHex).join('|');
	const approvalCountSignal = account.approvalCount;
	React.useEffect(() => {
		// Touch the trigger keys so the linter accepts them as deps; they're
		// identity-stable signals that re-key the effect, not values used inside.
		void membersKey;
		void approvalCountSignal;
		let cancelled = false;
		(async () => {
			const slots = membersRef.current;
			const pdas = slots.map((slot) => approvalPda(proposalAddress, memberIdHash(slot)));
			const infos = await connection.getMultipleAccountsInfo(pdas, 'confirmed');
			if (cancelled) return;
			const out: Uint8Array[] = [];
			for (let i = 0; i < infos.length; i++) {
				if (infos[i]) out.push(slots[i] as Uint8Array);
			}
			setVoters(out);
		})();
		return () => {
			cancelled = true;
		};
	}, [proposalAddress, connection, membersKey, approvalCountSignal]);

	const myMemberSlot = React.useMemo(() => {
		if (!meSlot) return null;
		const meHash = memberIdHash(meSlot);
		return (
			vault.account.members.find((slot) =>
				bytesEq(memberIdHash(slot).toBytes(), meHash.toBytes()),
			) ?? null
		);
	}, [meSlot, vault.account.members]);

	const isMember = myMemberSlot !== null;
	const alreadyVoted = React.useMemo(() => {
		if (!myMemberSlot) return false;
		const myHash = memberIdHash(myMemberSlot).toBytes();
		return voters.some((slot) => bytesEq(memberIdHash(slot).toBytes(), myHash));
	}, [myMemberSlot, voters]);

	// Sticky bundle preview. After execute the on-chain proposal stays;
	// but the SweepBundle in IndexedDB is the only source of the destination
	// and amount values. Stick the last non-null view so a post-execute
	// refresh keeps the numbers visible.
	const [sweepBundle, setSweepBundle] = React.useState<SweepBundle | null | 'pending'>('pending');
	React.useEffect(() => {
		let cancelled = false;
		loadSweepBundle(proposalAddress.toBase58()).then((p) => {
			if (!cancelled) setSweepBundle(p);
		});
		return () => {
			cancelled = true;
		};
	}, [proposalAddress]);

	const txCount = account.intentDigests.length;
	const stickyBundleRef = React.useRef<{
		txCount: number;
		totalLamports: bigint;
		splCount: number;
		destination: string;
	} | null>(null);
	const bundleView = React.useMemo(() => {
		if (sweepBundle && sweepBundle !== 'pending') {
			const sweepLamports =
				BigInt(sweepBundle.solBalanceLamports) - BigInt(sweepBundle.feeReserveLamports);
			stickyBundleRef.current = {
				txCount,
				totalLamports: sweepLamports,
				splCount: sweepBundle.tokenAccounts.length,
				destination: sweepBundle.destination,
			};
		}
		return stickyBundleRef.current;
	}, [sweepBundle, txCount]);

	const approvalsNum = account.approvalCount;
	const thresholdNum = vault.account.threshold;
	const ratio = thresholdNum === 0 ? 1 : Math.min(1, approvalsNum / thresholdNum);
	const reachedThreshold = account.status === STATUS_APPROVED || approvalsNum >= thresholdNum;
	const executed = account.status === STATUS_EXECUTED;

	const [actionState, setActionState] = React.useState<
		| { stage: 'idle' }
		| { stage: 'approving' }
		| { stage: 'executing'; phaseLabel?: string }
		| { stage: 'broadcasting' }
		| { stage: 'broadcasted'; result: BroadcastResult }
		| { stage: 'error'; message: string }
	>({ stage: 'idle' });

	async function handleApprove() {
		if (!gasPayer) return;
		if (!voter) {
			setActionState({
				stage: 'error',
				message:
					"You're not on this vault's roster. Reconnect with the wallet or passkey that's a member.",
			});
			return;
		}
		setActionState({ stage: 'approving' });
		try {
			await approveAsMember({
				connection,
				primaryWallet: gasPayer.wallet,
				voter,
				recovery: vault.recovery,
				recoveryId: vault.account.recoveryId,
				proposal: proposalAddress,
				proposalIndex,
				dwalletPubkey: vault.dwalletPubkey,
				dwalletAccount: vault.dwalletAccount,
			});
			setActionState({ stage: 'idle' });
			await queryClient.invalidateQueries({
				queryKey: ['solana-proposal', vault.recovery.toBase58(), proposalIndex],
			});
			await queryClient.invalidateQueries({
				queryKey: ['solana-vault', recoveryId],
			});
		} catch (e) {
			setActionState({
				stage: 'error',
				message: e instanceof Error ? e.message : String(e),
			});
		}
	}

	async function handleExecute() {
		if (!gasPayer) return;
		if (!bundle) {
			setActionState({
				stage: 'error',
				message:
					'DKG bundle missing on this device. Broadcast from the wallet that sealed the vault.',
			});
			return;
		}
		if (!sweepBundle || sweepBundle === 'pending') {
			setActionState({
				stage: 'error',
				message: 'Sweep bundle not on this device. Broadcast from the wallet that proposed.',
			});
			return;
		}
		setActionState({ stage: 'executing' });
		try {
			const sweepMessages = await rebuildBundleMessages(connection, sweepBundle);
			const result = await executeAndBroadcast({
				connection,
				primaryWallet: gasPayer.wallet,
				recovery: vault.recovery,
				recoveryId: vault.account.recoveryId,
				proposal: proposalAddress,
				dkg: bundle,
				bundle: sweepBundle,
				sweepMessages,
				onProgress: (phase, detail) =>
					setActionState((s) =>
						s.stage === 'executing' || s.stage === 'broadcasting'
							? phase === 'broadcasting'
								? { stage: 'broadcasting' }
								: {
										stage: 'executing',
										phaseLabel: detail ?? executePhaseLabel(phase),
									}
							: s,
					),
			});
			setActionState({ stage: 'broadcasted', result });
			await queryClient.invalidateQueries({
				queryKey: ['solana-proposal', vault.recovery.toBase58(), proposalIndex],
			});
			await queryClient.invalidateQueries({
				queryKey: ['solana-vault', recoveryId],
			});
		} catch (e) {
			setActionState({
				stage: 'error',
				message: e instanceof Error ? e.message : String(e),
			});
		}
	}

	return (
		<>
			<BackToVaultLink
				recoveryId={recoveryId}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-8"
			/>

			<header className="mb-8">
				<span className="smallcaps text-clay">Recovery proposal</span>
				<h1 className="mt-3 font-display text-[40px] sm:text-[56px] lg:text-[72px] leading-[0.98] tracking-[-0.025em] text-text">
					#{proposalIdStr}
				</h1>
				<p className="mt-4 max-w-[640px] text-[15px] text-text-2 leading-[1.6]">
					{txCount === 1
						? 'One Solana transaction in this bundle.'
						: `${txCount} Solana transactions in this bundle.`}{' '}
					The dWallet signs each one once a quorum of {thresholdNum} approval
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
								executed ? 'text-text-3' : reachedThreshold ? 'text-sage' : 'text-clay',
							)}
						>
							{executed ? (
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
						{voters.length === 0 && (
							<li className="px-5 sm:px-8 py-4 text-[13px] text-text-3">No approvals yet.</li>
						)}
						{voters.map((slot, i) => (
							<li
								key={i}
								className="px-5 sm:px-8 py-3 font-mono text-[12px] tabular text-text-2 break-all"
							>
								{voterLabel(slot)} · {bytesToHex(slot)}
							</li>
						))}
					</ul>
				</Card>

				{/* Bundle preview */}
				<Card tone="raised" className="lg:col-span-5 p-0 overflow-hidden">
					<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-3">Bundle</span>
						<span className="font-mono text-[10.5px] tabular text-text-4 break-all">
							{account.intentDigests[0]
								? `${bytesToHex(account.intentDigests[0]).slice(0, 12)}…`
								: '—'}
						</span>
					</div>
					{bundleView ? (
						<>
							<div className="divide-y divide-border">
								<Stat
									label="Transactions"
									value={`${bundleView.txCount}`}
									hint={
										bundleView.txCount === 1
											? 'Single sweep.'
											: 'All txs sign under one bundle digest.'
									}
								/>
								<Stat
									label="SOL transferred"
									value={`${(Number(bundleView.totalLamports) / 1e9).toFixed(6)} SOL`}
								/>
								{bundleView.splCount > 0 && (
									<Stat label="SPL transfers" value={`${bundleView.splCount}`} />
								)}
							</div>
							<div className="px-5 sm:px-8 py-4 border-t border-border">
								<span className="smallcaps text-text-3">Intent digests</span>
								<ol className="mt-3 space-y-2">
									{account.intentDigests.map((d, i) => {
										const executedBit = (account.executedBitmap & (1 << i)) !== 0;
										return (
											<li key={i} className="flex items-baseline gap-3 text-[12px]">
												<span className="font-mono text-[10.5px] text-text-4 tabular w-6 pt-0.5">
													{String(i + 1).padStart(2, '0')}
												</span>
												<span className="font-mono tabular text-text-2 break-all flex-1">
													{bytesToHex(d).slice(0, 24)}…
												</span>
												<span
													className={cn(
														'smallcaps tabular',
														executedBit ? 'text-sage' : 'text-text-4',
													)}
												>
													{executedBit ? 'done' : 'pending'}
												</span>
											</li>
										);
									})}
								</ol>
							</div>
						</>
					) : (
						<div className="px-5 sm:px-8 py-8 flex items-start gap-3">
							<ShieldCheck className="h-4 w-4 text-text-3 mt-0.5 flex-none" />
							<div className="text-[13px] text-text-2 leading-[1.55]">
								<div className="smallcaps text-text-3 mb-1">Bundle missing</div>
								The sweep bundle isn&apos;t on this device. The intent digests above are the
								canonical identifiers; broadcast from the wallet that proposed.
							</div>
						</div>
					)}
				</Card>
			</div>

			{/* Signer + gas-payer */}
			{!executed && actionState.stage !== 'broadcasted' && (
				<div className="mt-6">
					<SignerGasPayerCard
						state={signer.state}
						onPickSigner={signer.pickSigner}
						onPickGas={signer.pickGas}
						rosterSize={vault.account.members.length}
					/>
				</div>
			)}

			{/* Action footer */}
			{!executed && actionState.stage !== 'broadcasted' && (
				<div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-end gap-3">
					{actionState.stage === 'error' && (
						<p className="flex-1 text-[12.5px] text-clay leading-[1.5] inline-flex items-start gap-1.5">
							<AlertCircle className="h-3.5 w-3.5 mt-0.5 flex-none" />
							{actionState.message}
						</p>
					)}
					<Button
						variant="secondary"
						size="lg"
						disabled={
							!isMember ||
							!gasPayer ||
							alreadyVoted ||
							reachedThreshold ||
							executed ||
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
								{reachedThreshold && !alreadyVoted
									? 'Quorum reached'
									: alreadyVoted
										? 'You approved'
										: 'Approve'}
							</>
						)}
					</Button>
					<Button
						variant="irreversible"
						size="lg"
						disabled={
							!reachedThreshold ||
							executed ||
							!bundle ||
							!sweepBundle ||
							sweepBundle === 'pending' ||
							!gasPayer ||
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
								Broadcasting…
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
							Broadcast complete
						</span>
						<span className="font-mono text-[12px] tabular text-text">
							{(actionState.result.totalLamports / 1e9).toFixed(6)} SOL
						</span>
					</div>
					<ul className="divide-y divide-border">
						{actionState.result.executeSigs.map((execSig, i) => {
							const broadcastSig = actionState.result.broadcastSigs[i] ?? '';
							return (
								<React.Fragment key={i}>
									<li className="px-6 py-3 flex items-center gap-3 text-[13px]">
										<span className="font-mono text-[10.5px] text-text-4 tabular w-20 flex-none">
											Tx {String(i + 1).padStart(2, '0')} · execute
										</span>
										<CheckCircle2 className="h-3.5 w-3.5 text-sage flex-none" />
										<a
											href={solanaExplorerTx(execSig)}
											target="_blank"
											rel="noopener noreferrer"
											className="flex-1 font-mono text-[12px] tabular text-text break-all hover:text-clay inline-flex items-center gap-1.5"
										>
											{execSig}
											<ExternalLink className="h-3 w-3 flex-none text-text-3" />
										</a>
									</li>
									<li className="px-6 py-3 flex items-center gap-3 text-[13px]">
										<span className="font-mono text-[10.5px] text-text-4 tabular w-20 flex-none">
											Tx {String(i + 1).padStart(2, '0')} · sweep
										</span>
										<CheckCircle2 className="h-3.5 w-3.5 text-sage flex-none" />
										<a
											href={solanaExplorerTx(broadcastSig)}
											target="_blank"
											rel="noopener noreferrer"
											className="flex-1 font-mono text-[12px] tabular text-text break-all hover:text-clay inline-flex items-center gap-1.5"
										>
											{broadcastSig}
											<ExternalLink className="h-3 w-3 flex-none text-text-3" />
										</a>
									</li>
								</React.Fragment>
							);
						})}
					</ul>
					<div className="px-6 py-4 border-t border-border flex items-center justify-between">
						<span className="text-[12.5px] text-text-3">
							Recipient{' '}
							<span className="font-mono tabular text-text">
								{actionState.result.recipient.toBase58()}
							</span>
						</span>
						<Button
							variant="ghost"
							size="default"
							onClick={() => router.push(`/vault/${recoveryId}`)}
						>
							Back to vault
						</Button>
					</div>
				</Card>
			)}
		</>
	);
}

function ProposalSkeleton({ recoveryId, idStr }: { recoveryId: string; idStr: string }) {
	return (
		<>
			<BackToVaultLink
				recoveryId={recoveryId}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-8"
			/>
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
						<span className="smallcaps text-text-3">Bundle</span>
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

function voterLabel(slot: Uint8Array): string {
	if (slot.length === 0) return '?';
	switch (slot[0]) {
		case 0:
			return 'Ed25519';
		case 1:
			return 'Secp256k1';
		case 2:
			return 'Secp256r1';
		case 3:
			return 'Passkey';
		case 4:
			return 'Solana';
		default:
			return '?';
	}
}

function executePhaseLabel(phase: RecoverPhase): string {
	switch (phase) {
		case 'ensuring-alt':
			return 'Preparing lookup table…';
		case 'executing':
			return 'Submitting execute tx…';
		case 'signing':
			return 'Network signing…';
		case 'broadcasting':
			return 'Broadcasting…';
		case 'approving':
			return 'Approving…';
		case 'proposing':
			return 'Proposing…';
		case 'awaiting-approvals':
			return 'Awaiting approvals…';
		case 'done':
			return 'Done';
		default:
			return 'Working…';
	}
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function solanaExplorerTx(sig: string): string {
	const cluster = SOLANA_RPC.includes('devnet')
		? '?cluster=devnet'
		: SOLANA_RPC.includes('testnet')
			? '?cluster=testnet'
			: '';
	return `https://explorer.solana.com/tx/${sig}${cluster}`;
}
