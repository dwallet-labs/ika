'use client';

import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import {
	memberIdBytes,
	memberIdHash,
	rosterChangeApprovalPda,
	SCHEME_SOLANA_ADDRESS,
	STATUS_EXECUTED,
} from '@fesal-packages/ikavery-solana-sdk';
import { Connection, PublicKey } from '@solana/web3.js';
import {
	AlertCircle,
	ArrowLeft,
	CheckCircle2,
	ExternalLink,
	Loader2,
	Send,
	ShieldAlert,
	Signature,
	Trash2,
	UserMinus,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { SignerGasPayerCard, useSignerState } from '@/components/vault/signer-gas-payer';
import { SOLANA_RPC } from '@/lib/env';
import { approveRosterAsMember, executeRoster, type RosterPhase } from '@/lib/roster';
import { useRosterChangeQuery } from '@/lib/use-roster-change';
import { useVaultQuery, type VaultState } from '@/lib/use-vault';
import { memberSlotForVoter } from '@/lib/voter';

const SOLSCAN_BASE = 'https://solscan.io';
const SOLSCAN_CLUSTER = '?cluster=devnet';

export default function RosterChangeApprovalPage() {
	const params = useParams<{ recoveryId: string; id: string }>();
	const recoveryId = params.recoveryId;
	const rosterChangeIndex = Number.parseInt(params.id, 10);

	const vaultQ = useVaultQuery(recoveryId);
	const rosterQ = useRosterChangeQuery(
		vaultQ.data?.recovery ?? null,
		Number.isFinite(rosterChangeIndex) ? rosterChangeIndex : null,
	);

	if (!Number.isFinite(rosterChangeIndex)) {
		return (
			<BlockedShell title="Bad roster change id" recoveryId={recoveryId}>
				Index <span className="font-mono">{params.id}</span> isn&apos;t a valid integer.
			</BlockedShell>
		);
	}
	if (vaultQ.isLoading || rosterQ.isLoading) return <Skeleton />;
	if (vaultQ.error || !vaultQ.data) {
		return (
			<BlockedShell title="Couldn't open this vault" recoveryId={recoveryId}>
				<span className="font-mono break-all">
					{vaultQ.error instanceof Error ? vaultQ.error.message : String(vaultQ.error)}
				</span>
			</BlockedShell>
		);
	}
	if (!rosterQ.data?.account) {
		return (
			<BlockedShell title="Roster change not found" recoveryId={recoveryId}>
				Index {rosterChangeIndex} doesn&apos;t exist on this vault.
			</BlockedShell>
		);
	}

	return (
		<View
			recoveryId={recoveryId}
			vault={vaultQ.data}
			rosterChange={rosterQ.data.rosterChange}
			rosterChangeIndex={rosterChangeIndex}
			account={rosterQ.data.account}
		/>
	);
}

function View({
	recoveryId,
	vault,
	rosterChange,
	rosterChangeIndex,
	account,
}: {
	recoveryId: string;
	vault: VaultState;
	rosterChange: PublicKey;
	rosterChangeIndex: number;
	account: NonNullable<ReturnType<typeof useRosterChangeQuery>['data']>['account'];
}) {
	const router = useRouter();
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);

	const signer = useSignerState({ members: vault.account.members });
	const voter = signer.voterFromActive();
	const gasPayer = signer.state.gasPayer;
	const meSlot = React.useMemo(() => (voter ? memberSlotForVoter(voter) : null), [voter]);
	const isMember = voter !== null;

	const [hasMyApproval, setHasMyApproval] = React.useState<boolean | 'checking'>('checking');
	const approvalCountSignal = account?.approvalCount;
	// biome-ignore lint/correctness/useExhaustiveDependencies: approvalCountSignal is the manual invalidation key, not a value the effect reads.
	React.useEffect(() => {
		if (!meSlot || !isMember) {
			setHasMyApproval(false);
			return;
		}
		let cancelled = false;
		(async () => {
			const memberHash = memberIdHash(meSlot);
			const approval = rosterChangeApprovalPda(rosterChange, memberHash);
			const info = await connection.getAccountInfo(approval, 'confirmed');
			if (!cancelled) setHasMyApproval(info !== null);
		})();
		return () => {
			cancelled = true;
		};
	}, [rosterChange, meSlot, isMember, connection, approvalCountSignal]);

	const [busy, setBusy] = React.useState<RosterPhase | null>(null);
	const [executeSig, setExecuteSig] = React.useState<string | null>(null);
	const [error, setError] = React.useState<string | null>(null);

	if (!account) return null;

	const status = account.status;
	const approvalCount = account.approvalCount;
	const threshold = vault.account.threshold;
	const reachedThreshold = approvalCount >= threshold;
	const executed = status === STATUS_EXECUTED || executeSig !== null;
	const newThresholdValue = account.hasNewThreshold ? account.newThreshold : null;

	const removalRows = account.removals.map((slot) => {
		const live = vault.account.members.find((m) => bytesEq(memberIdBytes(m), memberIdBytes(slot)));
		return { slot, member: live ?? null };
	});
	const newThresholdLabel =
		newThresholdValue === null ? `kept at ${threshold}` : `→ ${newThresholdValue}`;
	// Once executed, `vault.account.members` already reflects the post-state
	// — subtracting removals again would double-count. Same logic on Sui.
	const postCount = executed
		? vault.account.members.length
		: vault.account.members.length - account.removals.length + account.additions.length;

	async function handleApprove() {
		if (!gasPayer) return;
		if (!voter) {
			setError(
				"You're not on this vault's roster. Reconnect with the wallet or passkey that's a member.",
			);
			return;
		}
		setError(null);
		setBusy('ensuring-alt');
		try {
			await approveRosterAsMember({
				connection,
				primaryWallet: gasPayer.wallet,
				voter,
				recovery: vault.recovery,
				recoveryId: vault.account.recoveryId,
				rosterChange,
				rosterChangeIndex,
				dwalletPubkey: vault.dwalletPubkey,
				dwalletAccount: vault.dwalletAccount,
				onProgress: (p) => setBusy(p),
			});
			setBusy(null);
			setHasMyApproval(true);
		} catch (e) {
			setError(e instanceof Error ? e.message : String(e));
			setBusy(null);
		}
	}

	async function handleExecute() {
		if (!gasPayer) return;
		setError(null);
		setBusy('executing');
		try {
			const r = await executeRoster({
				connection,
				primaryWallet: gasPayer.wallet,
				recovery: vault.recovery,
				rosterChange,
				onProgress: (p) => setBusy(p),
			});
			setExecuteSig(r.signature);
			setBusy(null);
		} catch (e) {
			setError(e instanceof Error ? e.message : String(e));
			setBusy(null);
		}
	}

	return (
		<div className="max-w-[820px] mx-auto py-10">
			<button
				type="button"
				onClick={() => router.push(`/vault/${recoveryId}`)}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-6"
			>
				<ArrowLeft className="h-3 w-3" />
				Back to vault
			</button>

			<header className="mb-6">
				<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<UserMinus className="h-3 w-3" />
					Roster change #{String(rosterChangeIndex).padStart(2, '0')}
				</div>
				<h1 className="mt-2 font-display text-[32px] sm:text-[38px] leading-[1.05] text-text">
					{executed ? 'Roster change applied' : 'Approve & execute'}
				</h1>
			</header>

			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Members to remove</span>
					<span className="font-mono text-[12px] text-text-3 tabular">
						{account.removals.length} removal
						{account.removals.length === 1 ? '' : 's'}
					</span>
				</div>
				{account.removals.length === 0 ? (
					<div className="px-5 sm:px-8 py-5 text-[13px] text-text-3">
						None — this proposal only changes the threshold.
					</div>
				) : (
					<ul className="divide-y divide-border">
						{removalRows.map((row) => {
							const slot = row.member ?? row.slot;
							return (
								<li key={slotKey(row.slot)} className="px-5 sm:px-8 py-3">
									<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
										<Trash2 className="h-3 w-3 text-clay" />
										{row.member ? schemeLabel(slot[0] ?? 0) : 'Unknown member'}
									</div>
									<div className="mt-1 font-mono text-[12px] tabular text-text break-all">
										{slotDisplay(slot)}
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
								{newThresholdValue ?? threshold}
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
						{approvalCount} / {threshold}
					</span>
				</div>
			</Card>

			{!executed && (
				<div className="mt-4">
					<SignerGasPayerCard
						state={signer.state}
						onPickSigner={signer.pickSigner}
						onPickGas={signer.pickGas}
						rosterSize={vault.account.members.length}
					/>
				</div>
			)}

			{!executed && (
				<div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-end gap-3">
					{error && <p className="flex-1 text-[12.5px] text-clay leading-[1.5]">{error}</p>}
					<Button
						variant="secondary"
						size="lg"
						disabled={
							!isMember || !gasPayer || hasMyApproval === true || reachedThreshold || busy !== null
						}
						onClick={handleApprove}
					>
						{busy === 'ensuring-alt' || busy === 'approving' ? (
							<>
								<Loader2 className="h-4 w-4 animate-spin" />
								Approving…
							</>
						) : hasMyApproval === true ? (
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
						disabled={!reachedThreshold || !gasPayer || busy !== null}
						onClick={handleExecute}
					>
						{busy === 'executing' ? (
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

			{!executed && (
				<Card tone="raised" className="mt-4 px-6 py-4 border-border">
					<p className="text-[12.5px] text-text-3 leading-[1.55] inline-flex items-start gap-2">
						<AlertCircle className="h-3.5 w-3.5 text-text-3 flex-none mt-0.5" />
						<span>
							Apply doesn&apos;t touch Ika or the dWallet — it only mutates the members set +
							threshold on the recovery PDA. No IKA fee.
						</span>
					</p>
				</Card>
			)}

			{executed && (
				<Card tone="raised" className="mt-6 px-6 py-5 border-sage/40">
					<div className="flex items-start gap-3">
						<CheckCircle2 className="h-4 w-4 text-sage mt-0.5 flex-none" />
						<div className="flex-1 min-w-0">
							<div className="smallcaps text-sage">Roster updated</div>
							<p className="mt-1 text-[13px] text-text-2 leading-[1.55]">
								{account.removals.length > 0
									? `${account.removals.length} member${account.removals.length === 1 ? '' : 's'} removed.`
									: ''}
								{newThresholdValue !== null
									? ` New threshold ${newThresholdValue} of ${vault.account.members.length}.`
									: ''}
							</p>
							{executeSig && (
								<a
									href={`${SOLSCAN_BASE}/tx/${executeSig}${SOLSCAN_CLUSTER}`}
									target="_blank"
									rel="noopener noreferrer"
									className="mt-3 inline-flex items-center gap-1.5 font-mono text-[12px] tabular text-text-2 hover:text-clay break-all"
								>
									{executeSig.slice(0, 14)}…{executeSig.slice(-8)}
									<ExternalLink className="h-3 w-3 flex-none" />
								</a>
							)}
						</div>
					</div>
				</Card>
			)}
		</div>
	);
}

function BlockedShell({
	title,
	children,
	recoveryId,
}: {
	title: string;
	children: React.ReactNode;
	recoveryId: string;
}) {
	const router = useRouter();
	return (
		<div className="max-w-[640px] mx-auto py-12">
			<Card tone="raised" className="p-5 sm:p-8">
				<div className="flex items-start gap-3">
					<ShieldAlert className="h-5 w-5 text-clay mt-0.5" />
					<div>
						<h2 className="font-display text-[26px] text-text leading-[1.05]">{title}</h2>
						<div className="mt-3 text-[14px] text-text-2 leading-[1.55]">{children}</div>
						<div className="mt-6">
							<Button
								variant="ghost"
								size="default"
								onClick={() => router.push(`/vault/${recoveryId}`)}
							>
								<ArrowLeft className="h-3.5 w-3.5" />
								Back to vault
							</Button>
						</div>
					</div>
				</div>
			</Card>
		</div>
	);
}

function Skeleton() {
	return (
		<div className="max-w-[820px] mx-auto py-10 space-y-4">
			<div className="h-3 w-32 bg-surface-2 rounded animate-pulse" />
			<div className="h-12 w-72 bg-surface-2 rounded animate-pulse" />
			<Card tone="raised" className="p-5 sm:p-8">
				<div className="space-y-3">
					<div className="h-4 w-24 bg-surface-2 rounded animate-pulse" />
					<div className="h-10 bg-surface-2 rounded animate-pulse" />
				</div>
			</Card>
		</div>
	);
}

function slotDisplay(slot: Uint8Array): string {
	if (slot[0] === SCHEME_SOLANA_ADDRESS) {
		try {
			return new PublicKey(slot.slice(1, 33)).toBase58();
		} catch {
			return '<bad slot>';
		}
	}
	return `0x${Array.from(memberIdBytes(slot), (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

function schemeLabel(scheme: number): string {
	switch (scheme) {
		case 0:
			return 'Ed25519';
		case 1:
			return 'Secp256k1';
		case 2:
			return 'Secp256r1';
		case 3:
			return 'Passkey';
		case SCHEME_SOLANA_ADDRESS:
			return 'Solana wallet';
		default:
			return `Scheme ${scheme}`;
	}
}

function slotKey(slot: Uint8Array): string {
	return Array.from(slot, (b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}
