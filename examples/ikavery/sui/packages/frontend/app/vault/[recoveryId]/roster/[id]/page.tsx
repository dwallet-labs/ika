'use client';

import { Button, Card, ProposalDetailSkeleton } from '@fesal-packages/ikavery-frontend-ui';
import { readRosterChange, type RosterChangeSnapshot } from '@fesal-packages/ikavery-sui-sdk';
import { useWalletConnection, useWallets } from '@mysten/dapp-kit-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
	AlertCircle,
	ArrowLeft,
	CheckCircle2,
	Loader2,
	Send,
	Signature,
	Trash2,
	UserMinus,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { ErrorShell } from '@/components/vault/error-shell';
import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { resolveCredentialRequest, signerOptionToIdentity } from '@/lib/credential-bridge';
import { dAppKit } from '@/lib/dapp-kit';
import { env } from '@/lib/env';
import { bytesToHex, renderMemberIdentity, schemeLabel } from '@/lib/format';
import { ESTIMATE_APPROVE } from '@/lib/gas-preflight';
import { buildRecoveryClient } from '@/lib/recovery-client';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import { bytesEq } from '@/lib/recovery-state';
import { buildSignAndExecute } from '@/lib/sponsored-sign';
import { useVaultQuery } from '@/lib/use-vault';

type ActionState =
	| { stage: 'idle' }
	| { stage: 'approving' }
	| { stage: 'executing' }
	| { stage: 'done' }
	| { stage: 'error'; message: string };

export default function RosterChangeDetailPage() {
	const router = useRouter();
	const params = useParams<{ recoveryId: string; id: string }>();
	const recoveryId = params.recoveryId;
	const rosterChangeIdStr = params.id;
	const rosterChangeId = React.useMemo(() => {
		try {
			return BigInt(rosterChangeIdStr);
		} catch {
			return null;
		}
	}, [rosterChangeIdStr]);

	const { suiClient, session } = useRecoveryClient();
	const wallets = useWallets();
	const { wallet: currentWallet } = useWalletConnection();
	const walletSign = dAppKit.signTransaction;
	const queryClient = useQueryClient();

	const vault = useVaultQuery(recoveryId);

	const snapshot = useQuery({
		queryKey: ['roster-change', recoveryId, rosterChangeIdStr, suiClient ? 'ready' : '_'],
		queryFn: async (): Promise<RosterChangeSnapshot> => {
			const recClient = buildRecoveryClient(suiClient!, recoveryId);
			return await readRosterChange(recClient, rosterChangeId!);
		},
		enabled: !!suiClient && rosterChangeId !== null,
		refetchInterval: 4_000,
	});

	const signerState = useSignerState(vault.data);
	const [actionState, setActionState] = React.useState<ActionState>({
		stage: 'idle',
	});

	async function handleApprove() {
		if (!session || !suiClient || !snapshot.data || rosterChangeId === null) return;
		if (!signerState.state.ready || !signerState.state.active || !signerState.state.gasPayer) {
			setActionState({
				stage: 'error',
				message: 'Pick a signer and a gas payer first.',
			});
			return;
		}
		const active = signerState.state.active;
		const gasPayer = signerState.state.gasPayer;
		setActionState({ stage: 'approving' });
		try {
			const signAndExecute = buildSignAndExecute({
				gasPayer,
				currentWallet: currentWallet ?? null,
				walletSign: async ({ transaction }) => await walletSign({ transaction }),
				suiClient,
				network: env.network,
			});
			await session.runApproveRosterChange({
				walletAddress: gasPayer.address,
				signAndExecute,
				resolveCredential: (challenge, identity) =>
					resolveCredentialRequest(challenge, identity, { wallets }),
				recoveryId,
				rosterChangeId: rosterChangeIdStr,
				authIdentity: signerOptionToIdentity(active),
			});
			setActionState({ stage: 'idle' });
			await queryClient.invalidateQueries({
				queryKey: ['roster-change', recoveryId, rosterChangeIdStr],
			});
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setActionState({ stage: 'error', message });
		}
	}

	async function handleExecute() {
		if (!session || !suiClient || !snapshot.data || !vault.data || rosterChangeId === null) return;
		if (!signerState.state.ready || !signerState.state.gasPayer) {
			setActionState({
				stage: 'error',
				message: 'Pick a gas payer first.',
			});
			return;
		}
		const gasPayer = signerState.state.gasPayer;
		setActionState({ stage: 'executing' });
		try {
			const signAndExecute = buildSignAndExecute({
				gasPayer,
				currentWallet: currentWallet ?? null,
				walletSign: async ({ transaction }) => await walletSign({ transaction }),
				suiClient,
				network: env.network,
			});
			await session.runExecuteRosterChange({
				walletAddress: gasPayer.address,
				signAndExecute,
				recoveryId,
				rosterChangeId: rosterChangeIdStr,
			});
			setActionState({ stage: 'done' });
			await queryClient.invalidateQueries({
				queryKey: ['roster-change', recoveryId, rosterChangeIdStr],
			});
			await queryClient.invalidateQueries({
				queryKey: ['vault', recoveryId],
			});
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			setActionState({ stage: 'error', message });
		}
	}

	if (rosterChangeId === null) {
		return <ErrorShell recoveryId={recoveryId} message="Invalid roster-change id." />;
	}

	if (snapshot.isLoading || !snapshot.data || !vault.data) {
		return (
			<ProposalDetailSkeleton
				recoveryId={recoveryId}
				idStr={rosterChangeIdStr}
				kindLabel="Roster change"
				Icon={UserMinus}
			/>
		);
	}

	const snap = snapshot.data;
	const threshold = vault.data.threshold;
	const approvalsNum = Number(snap.approvals);
	const reachedThreshold = approvalsNum >= threshold;
	const myMemberId = signerState.state.active?.member.id ?? null;
	const alreadyVoted = myMemberId ? snap.voters.some((v) => bytesEq(v, myMemberId)) : false;

	// Resolve removal ids → live members for nicer rendering. Members already
	// removed in a prior race-execute will be shown as raw ids.
	const removalRows = snap.membersToRemove.map((id) => {
		const live = vault.data?.members.find((m) => bytesEq(m.id, id));
		return { id, member: live ?? null };
	});
	const newThresholdLabel =
		snap.newThreshold === null ? `kept at ${threshold}` : `→ ${snap.newThreshold.toString()}`;
	// Once executed, `vault.data.members` already reflects the post-state —
	// subtracting `membersToRemove` again would double-count.
	const postCount = snap.executed
		? vault.data.members.length
		: vault.data.members.length - snap.membersToRemove.length;

	return (
		<div className="max-w-[820px] mx-auto py-10">
			<button
				onClick={() => router.push(`/vault/${recoveryId}`)}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-6"
			>
				<ArrowLeft className="h-3 w-3" />
				Back to vault
			</button>

			<header className="mb-6">
				<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<UserMinus className="h-3 w-3" />
					Roster change #{rosterChangeIdStr}
				</div>
				<h1 className="mt-2 font-display text-[32px] sm:text-[38px] leading-[1.05] text-text">
					{snap.executed ? 'Roster change applied' : 'Approve & execute'}
				</h1>
			</header>

			{/* Removals */}
			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Members to remove</span>
					<span className="font-mono text-[12px] text-text-3 tabular">
						{snap.membersToRemove.length} removal
						{snap.membersToRemove.length === 1 ? '' : 's'}
					</span>
				</div>
				{snap.membersToRemove.length === 0 ? (
					<div className="px-5 sm:px-8 py-5 text-[13px] text-text-3">
						None — this proposal only changes the threshold.
					</div>
				) : (
					<ul className="divide-y divide-border">
						{removalRows.map((row) => {
							const hex = bytesToHex(row.id);
							return (
								<li key={hex} className="px-5 sm:px-8 py-3">
									<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
										<Trash2 className="h-3 w-3 text-clay" />
										{row.member ? schemeLabel(row.member.scheme) : 'Unknown member'}
									</div>
									<div className="mt-1 font-mono text-[12px] tabular text-text break-all">
										{row.member ? renderMemberIdentity(row.member) : `0x${hex}`}
									</div>
								</li>
							);
						})}
					</ul>
				)}
				<div className="px-5 sm:px-8 py-4 border-t border-border flex items-baseline justify-between gap-4 flex-wrap">
					<div>
						<div className="smallcaps text-text-3">After execute</div>
						<div className="mt-1 flex items-baseline gap-2">
							<span className="font-display text-[28px] leading-[0.95] tabular text-text">
								{snap.newThreshold !== null ? snap.newThreshold.toString() : threshold}
							</span>
							<span className="font-display italic text-text-3 text-[14px] tracking-tight">of</span>
							<span className="font-display text-[28px] leading-[0.95] tabular text-text-2">
								{postCount}
							</span>
						</div>
					</div>
					<div className="text-right">
						<div className="smallcaps text-text-3">Threshold</div>
						<div className="mt-1 font-mono text-[12.5px] tabular text-text-2">
							{newThresholdLabel}
						</div>
					</div>
				</div>
				<div className="px-5 sm:px-8 py-4 border-t border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Approvals</span>
					<span
						className={`font-mono text-[20px] tabular ${
							reachedThreshold ? 'text-sage' : 'text-text'
						}`}
					>
						{approvalsNum} / {threshold}
					</span>
				</div>
			</Card>

			{/* Signer + gas-payer */}
			{!snap.executed && (
				<div className="mt-4">
					<SignerGasPayerCard
						vault={vault.data}
						state={signerState.state}
						onPickSigner={signerState.pickSigner}
						onPickGas={signerState.pickGas}
						estimate={ESTIMATE_APPROVE}
					/>
				</div>
			)}

			{/* Action footer */}
			{!snap.executed && (
				<div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-end gap-3">
					{actionState.stage === 'error' && (
						<p className="flex-1 text-[12.5px] text-clay leading-[1.5]">{actionState.message}</p>
					)}
					<Button
						variant="secondary"
						size="lg"
						disabled={
							!signerState.state.ready ||
							alreadyVoted ||
							reachedThreshold ||
							actionState.stage === 'approving' ||
							actionState.stage === 'executing'
						}
						onClick={handleApprove}
					>
						{actionState.stage === 'approving' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Approving…
							</>
						) : alreadyVoted ? (
							<>
								<CheckCircle2 className="h-4 w-4" />
								You approved
							</>
						) : reachedThreshold ? (
							<>
								<CheckCircle2 className="h-4 w-4" />
								Quorum reached
							</>
						) : (
							<>
								<Signature className="h-4 w-4" />
								Approve
							</>
						)}
					</Button>
					<Button
						variant="irreversible"
						size="lg"
						disabled={
							!reachedThreshold ||
							!signerState.state.gasPayer ||
							actionState.stage === 'executing' ||
							actionState.stage === 'approving'
						}
						onClick={handleExecute}
					>
						{actionState.stage === 'executing' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Executing…
							</>
						) : (
							<>
								<Send className="h-4 w-4" />
								Apply roster change
							</>
						)}
					</Button>
				</div>
			)}

			{!snap.executed && (
				<Card tone="raised" className="mt-4 px-6 py-4 border-border">
					<p className="text-[12.5px] text-text-3 leading-[1.55] inline-flex items-start gap-2">
						<AlertCircle className="h-3.5 w-3.5 text-text-3 flex-none mt-0.5" />
						<span>
							Apply doesn’t touch Ika or the dWallet — it only mutates the members set + threshold
							on the recovery shared object. No IKA fee.
						</span>
					</p>
				</Card>
			)}

			{snap.executed && (
				<Card tone="raised" className="mt-6 px-6 py-5 border-sage/40">
					<div className="flex items-start gap-3">
						<CheckCircle2 className="h-4 w-4 text-sage mt-0.5 flex-none" />
						<div>
							<div className="smallcaps text-sage">Roster updated</div>
							<p className="mt-1 text-[13px] text-text-2 leading-[1.55]">
								{snap.membersToRemove.length > 0
									? `${snap.membersToRemove.length} member${snap.membersToRemove.length === 1 ? '' : 's'} removed.`
									: ''}
								{snap.newThreshold !== null
									? ` New threshold ${snap.newThreshold.toString()} of ${vault.data.members.length}.`
									: ''}
							</p>
						</div>
					</div>
				</Card>
			)}
		</div>
	);
}
