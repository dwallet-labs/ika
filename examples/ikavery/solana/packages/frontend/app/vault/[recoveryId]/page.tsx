'use client';

import { useDynamicContext } from '@dynamic-labs/sdk-react-core';
import {
	Button,
	Card,
	cn,
	ProposalCardSkeleton,
	truncateAddress,
} from '@fesal-packages/ikavery-frontend-ui';
import {
	memberIdBytes,
	SCHEME_ED25519,
	SCHEME_SECP256K1,
	SCHEME_SECP256R1,
	SCHEME_SOLANA_ADDRESS,
	SCHEME_WEBAUTHN,
	STATUS_EXECUTED,
} from '@fesal-packages/ikavery-solana-sdk';
import { PublicKey } from '@solana/web3.js';
import {
	AlertCircle,
	ArrowLeft,
	ArrowUpRight,
	Check,
	Copy,
	ExternalLink,
	Fingerprint,
	KeyRound,
	Loader2,
	ShieldCheck,
	Trash2,
	UserMinus,
	UserPlus,
	Wallet,
} from 'lucide-react';
import { useParams, useRouter } from 'next/navigation';
import * as React from 'react';

import { IKAVERY_PROGRAM_ID } from '@/lib/env';
import type { SweepBundle } from '@/lib/storage';
import {
	useDashboardActivity,
	type EnrollmentSnapshot,
	type ProposalSnapshot,
	type RosterChangeSnapshot,
} from '@/lib/use-dashboard-activity';
import { dwalletPdaFor, useVaultQuery, type VaultState } from '@/lib/use-vault';

const SOLSCAN_BASE = 'https://solscan.io';
const SOLSCAN_CLUSTER = '?cluster=devnet';
const FUND_THRESHOLD_LAMPORTS = 5_000_000; // ~0.005 SOL — covers a sweep tx

export default function VaultDashboard() {
	const params = useParams<{ recoveryId: string }>();
	const recoveryId = params.recoveryId;
	const router = useRouter();
	const { primaryWallet } = useDynamicContext();

	const state = useVaultQuery(recoveryId);

	if (state.isLoading) {
		return <VaultSkeleton recoveryId={recoveryId} />;
	}

	if (state.error) {
		return (
			<div className="max-w-[640px] mx-auto py-16">
				<button
					type="button"
					onClick={() => router.push('/vault')}
					className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-6"
				>
					<ArrowLeft className="h-3 w-3" />
					Back to directory
				</button>
				<Card tone="raised" className="px-5 sm:px-6 py-6 sm:py-7">
					<div className="flex items-start gap-4">
						<AlertCircle className="h-4 w-4 text-clay mt-1" />
						<div>
							<h2 className="font-display text-[24px] text-text">Couldn&apos;t open this vault.</h2>
							<p className="mt-2 text-[14px] text-text-2 leading-[1.55]">
								The Recovery PDA may be wrong, or the account lives on a different cluster. Check
								that you&apos;re on <span className="font-mono">solana devnet</span> and try again.
							</p>
							<div className="mt-3 font-mono text-[11px] tabular text-text-3 break-all">
								{state.error instanceof Error ? state.error.message : String(state.error)}
							</div>
						</div>
					</div>
				</Card>
			</div>
		);
	}

	if (!state.data) return null;
	const vault = state.data;

	const meAddress = primaryWallet?.address;
	const meIsMember =
		!!meAddress && vault.account.members.some((slot) => memberSlotMatchesAddress(slot, meAddress));

	return (
		<>
			<div className="mb-8 flex items-center justify-between">
				<button
					type="button"
					onClick={() => router.push('/vault')}
					className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5"
				>
					<ArrowLeft className="h-3 w-3" />
					Directory
				</button>
				<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<span className="h-1.5 w-1.5 rounded-full bg-sage" />
					Active on solana devnet
				</div>
			</div>

			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-10 pt-5 sm:pt-8 pb-2 flex items-baseline justify-between border-b border-border">
					<span className="smallcaps text-text-3">Recovery PDA</span>
					<span className="smallcaps text-text-4">
						ikavery {truncateAddress(IKAVERY_PROGRAM_ID, 4, 4)}
					</span>
				</div>
				<BlockId value={vault.recovery.toBase58()} accent="clay" big />
				<div className="rule-h" />
				<div className="px-5 sm:px-10 pt-5 pb-2 flex items-baseline justify-between border-t border-border">
					<span className="smallcaps text-text-3">dWallet pubkey</span>
					<span className="smallcaps text-text-4">Ika 2PC-MPC</span>
				</div>
				<BlockId value={vault.dwalletPubkey.toBase58()} accent="text" />
			</Card>

			<div className="mt-4 grid grid-cols-1 lg:grid-cols-12 gap-4">
				<Card tone="raised" className="lg:col-span-7 p-0 overflow-hidden">
					<SectionHead
						label="Members"
						right={
							<span className="font-mono text-[12px] text-text-3 tabular">
								{vault.account.members.length} total
							</span>
						}
					/>
					<ul className="divide-y divide-border">
						{vault.account.members.map((slot, i) => (
							<MemberRow
								key={`m:${i}`}
								slot={slot}
								isMe={!!meAddress && memberSlotMatchesAddress(slot, meAddress)}
							/>
						))}
					</ul>
				</Card>

				<div className="lg:col-span-5 grid grid-cols-1 gap-4">
					<Card tone="raised" className="p-0 overflow-hidden">
						<SectionHead label="Threshold" />
						<div className="px-5 sm:px-8 py-6 sm:py-7 flex items-baseline gap-2 sm:gap-3">
							<span className="font-display text-[52px] sm:text-[80px] leading-[0.9] tabular text-text">
								{vault.account.threshold}
							</span>
							<span className="font-display italic text-text-3 text-[20px] sm:text-[26px] tracking-tight">
								of
							</span>
							<span className="font-display text-[52px] sm:text-[80px] leading-[0.9] tabular text-text-2">
								{vault.account.members.length}
							</span>
						</div>
						<p className="px-5 sm:px-8 pb-5 text-[12.5px] text-text-3 leading-[1.55]">
							Recovery requires this many approvals. Members below the threshold cannot move funds
							alone.
						</p>
					</Card>

					<DwalletBalanceCard vault={vault} />
				</div>
			</div>

			<Card
				tone="raised"
				className="mt-4 px-5 sm:px-6 py-5 flex flex-col md:flex-row md:items-center gap-4"
			>
				<div className="flex items-start gap-3 sm:gap-4 flex-1 min-w-0">
					<div className="h-9 w-9 flex-none rounded border border-border flex items-center justify-center">
						{meIsMember ? (
							<ShieldCheck className="h-3.5 w-3.5 text-sage" />
						) : (
							<Wallet className="h-3.5 w-3.5 text-text-3" />
						)}
					</div>
					<div className="flex-1 min-w-0">
						<div className="smallcaps text-text-3">Your access</div>
						<p className="mt-1 text-[13.5px] text-text-2 leading-[1.55]">
							{meIsMember
								? 'Connected wallet is a member of this roster. You can propose recoveries, approve proposals, and propose enrollment / roster changes.'
								: meAddress
									? "Connected wallet is not in the member set. You can read the vault but can't act on it from here."
									: 'No wallet connected. Sign in via the widget in the header to act on this vault.'}
						</p>
					</div>
				</div>
				<div className="grid grid-cols-2 sm:flex sm:flex-wrap items-stretch sm:items-center gap-2 md:flex-none">
					<Button
						variant="irreversible"
						size="default"
						disabled={!meIsMember}
						onClick={() => router.push(`/vault/${recoveryId}/recover`)}
						className="col-span-2"
					>
						<KeyRound className="h-3.5 w-3.5" />
						Recover funds
					</Button>
					<Button
						variant="secondary"
						size="default"
						disabled={!meIsMember}
						onClick={() => router.push(`/vault/${recoveryId}/enroll`)}
					>
						<UserPlus className="h-3.5 w-3.5" />
						Add member
					</Button>
					<Button
						variant="secondary"
						size="default"
						disabled={!meIsMember}
						onClick={() => router.push(`/vault/${recoveryId}/roster`)}
					>
						<UserMinus className="h-3.5 w-3.5" />
						Edit roster
					</Button>
					<a
						href={`${SOLSCAN_BASE}/account/${vault.recovery.toBase58()}${SOLSCAN_CLUSTER}`}
						target="_blank"
						rel="noopener noreferrer"
						className="col-span-2 sm:col-span-1 inline-flex items-center justify-center sm:justify-start gap-1.5 smallcaps text-text-3 hover:text-text py-1"
					>
						<ArrowUpRight className="h-3 w-3" />
						Explorer
					</a>
				</div>
			</Card>

			<ActivitySections vault={vault} recoveryId={recoveryId} />
		</>
	);
}

function ActivitySections({ vault, recoveryId }: { vault: VaultState; recoveryId: string }) {
	const router = useRouter();
	const activity = useDashboardActivity({
		recovery: vault.recovery,
		proposalCount: vault.account.proposalCount,
		enrollmentCount: vault.account.enrollmentCount,
		rosterChangeCount: vault.account.rosterChangeCount,
	});

	const activeEnrollments =
		activity.data?.enrollments.filter((e) => e.account.status !== STATUS_EXECUTED) ?? [];
	const activeRosterChanges =
		activity.data?.rosterChanges.filter((r) => r.account.status !== STATUS_EXECUTED) ?? [];
	const proposals = activity.data?.proposals ?? [];

	return (
		<>
			{activeEnrollments.length > 0 && (
				<section className="mt-10">
					<header className="mb-3 flex items-baseline justify-between">
						<div className="smallcaps text-text-3">Active enrollments</div>
						<span className="font-mono text-[12px] text-text-3 tabular">
							{activeEnrollments.length} pending
						</span>
					</header>
					<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
						{activeEnrollments.map((e) => (
							<EnrollmentCard
								key={e.index}
								snap={e}
								threshold={vault.account.threshold}
								onClick={() => router.push(`/vault/${recoveryId}/enroll/${e.index}`)}
							/>
						))}
					</div>
				</section>
			)}

			{activeRosterChanges.length > 0 && (
				<section className="mt-10">
					<header className="mb-3 flex items-baseline justify-between">
						<div className="smallcaps text-text-3">Active roster changes</div>
						<span className="font-mono text-[12px] text-text-3 tabular">
							{activeRosterChanges.length} pending
						</span>
					</header>
					<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
						{activeRosterChanges.map((r) => (
							<RosterChangeCard
								key={r.index}
								snap={r}
								threshold={vault.account.threshold}
								totalMembers={vault.account.members.length}
								onClick={() => router.push(`/vault/${recoveryId}/roster/${r.index}`)}
							/>
						))}
					</div>
				</section>
			)}

			<section className="mt-10">
				<header className="mb-3 flex items-baseline justify-between">
					<div className="smallcaps text-text-3">Recovery proposals</div>
					{proposals.length > 0 && (
						<span className="font-mono text-[12px] text-text-3 tabular">
							{proposals.length} on record
						</span>
					)}
				</header>
				{vault.account.proposalCount === 0 ? (
					<Card tone="raised" className="px-5 sm:px-6 py-6 sm:py-7">
						<p className="text-[14px] text-text-2 leading-[1.55]">
							No recovery proposals yet. Initiate a sweep from{' '}
							<button
								type="button"
								onClick={() => router.push(`/vault/${recoveryId}/recover`)}
								className="text-clay hover:text-text underline-offset-2 hover:underline"
							>
								Recover funds
							</button>{' '}
							when you need to move funds out.
						</p>
					</Card>
				) : activity.isLoading ? (
					<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
						<ProposalCardSkeleton />
						<ProposalCardSkeleton />
					</div>
				) : (
					<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
						{proposals.map((p) => (
							<ProposalCard
								key={p.index}
								snap={p}
								threshold={vault.account.threshold}
								onClick={() => router.push(`/vault/${recoveryId}/proposal/${p.index}`)}
							/>
						))}
					</div>
				)}
			</section>
		</>
	);
}

function ProposalCard({
	snap,
	threshold,
	onClick,
}: {
	snap: ProposalSnapshot;
	threshold: number;
	onClick: () => void;
}) {
	const approvals = snap.account.approvalCount;
	const ratio = threshold === 0 ? 1 : Math.min(1, approvals / threshold);
	const reached = approvals >= threshold;
	const executed = snap.account.status === STATUS_EXECUTED;
	return (
		<button
			type="button"
			onClick={onClick}
			className="text-left surface-raised border border-border rounded-[var(--radius-card)] p-5 hover:border-border-strong hover:bg-surface-3 transition-colors group cursor-pointer w-full"
		>
			<div className="flex items-baseline justify-between gap-2 mb-3">
				<span className="font-display text-[28px] tabular text-text leading-[1]">
					#{snap.index}
				</span>
				<span
					className={cn(
						'smallcaps inline-flex items-center gap-1.5',
						executed ? 'text-text-3' : reached ? 'text-sage' : 'text-clay',
					)}
				>
					{executed ? (
						<>
							<ShieldCheck className="h-3 w-3" />
							Executed
						</>
					) : reached ? (
						<>
							<Check className="h-3 w-3" />
							Quorum
						</>
					) : (
						<>
							<Loader2 className="h-3 w-3" />
							Awaiting
						</>
					)}
				</span>
			</div>

			<div className="flex items-baseline gap-2 mb-3">
				<span
					className={cn(
						'font-display text-[40px] leading-[0.9] tabular',
						reached ? 'text-sage' : 'text-text',
					)}
				>
					{approvals}
				</span>
				<span className="font-display italic text-text-3 text-[16px] tracking-tight">of</span>
				<span className="font-display text-[40px] leading-[0.9] tabular text-text-2">
					{threshold}
				</span>
				<span className="ml-auto smallcaps text-text-3">
					{snap.account.intentDigests.length} tx
				</span>
			</div>

			<div className="h-1 w-full bg-surface-3 rounded overflow-hidden mb-3">
				<div
					className={cn('h-full transition-all duration-500', reached ? 'bg-sage' : 'bg-clay')}
					style={{ width: `${ratio * 100}%` }}
				/>
			</div>

			<div className="flex items-center justify-between gap-2">
				<span className="text-[12.5px] text-text-3 leading-[1.5]">
					{snap.bundle ? bundleSummary(snap.bundle) : 'intent locked on-chain'}
				</span>
				<span
					className={cn(
						'smallcaps inline-flex items-center gap-1 transition-colors',
						executed ? 'text-text-3 group-hover:text-text-2' : 'text-clay group-hover:text-text',
					)}
				>
					{executed ? 'View' : 'Open'}
					<ArrowUpRight className="h-3 w-3" />
				</span>
			</div>
		</button>
	);
}

function EnrollmentCard({
	snap,
	threshold,
	onClick,
}: {
	snap: EnrollmentSnapshot;
	threshold: number;
	onClick: () => void;
}) {
	const approvals = snap.account.approvalCount;
	const ratio = threshold === 0 ? 1 : Math.min(1, approvals / threshold);
	const reached = approvals >= threshold;
	const kindLabel = snap.account.additionApproverOnly ? 'Approver-only' : 'Wallet';
	const identity =
		snap.account.newMember[0] === SCHEME_SOLANA_ADDRESS
			? new PublicKey(snap.account.newMember.slice(1, 33)).toBase58()
			: Array.from(memberIdBytes(snap.account.newMember), (b) =>
					b.toString(16).padStart(2, '0'),
				).join('');
	return (
		<button
			type="button"
			onClick={onClick}
			className="text-left surface-raised border border-border rounded-[var(--radius-card)] p-5 hover:border-border-strong hover:bg-surface-3 transition-colors group cursor-pointer w-full"
		>
			<div className="flex items-baseline justify-between gap-2 mb-3">
				<span className="font-display text-[28px] tabular text-text leading-[1] inline-flex items-center gap-2">
					<UserPlus className="h-4 w-4 text-text-3" />#{snap.index}
				</span>
				<span className="smallcaps text-text-3">{kindLabel}</span>
			</div>

			<div className="font-mono text-[11.5px] tabular text-text-2 break-all leading-[1.45] mb-3">
				{identity}
			</div>

			<div className="flex items-baseline gap-2 mb-3">
				<span
					className={cn(
						'font-display text-[36px] leading-[0.9] tabular',
						reached ? 'text-sage' : 'text-text',
					)}
				>
					{approvals}
				</span>
				<span className="font-display italic text-text-3 text-[14px] tracking-tight">of</span>
				<span className="font-display text-[36px] leading-[0.9] tabular text-text-2">
					{threshold}
				</span>
				<span className="ml-auto smallcaps inline-flex items-center gap-1.5 text-text-3 group-hover:text-text">
					{reached ? (
						<>
							<Check className="h-3 w-3 text-sage" />
							Quorum
						</>
					) : (
						<>
							<Loader2 className="h-3 w-3" />
							Awaiting
						</>
					)}
				</span>
			</div>

			<div className="h-1 w-full bg-surface-3 rounded overflow-hidden mb-1">
				<div
					className={cn('h-full transition-all duration-500', reached ? 'bg-sage' : 'bg-clay')}
					style={{ width: `${ratio * 100}%` }}
				/>
			</div>
		</button>
	);
}

function RosterChangeCard({
	snap,
	threshold,
	totalMembers,
	onClick,
}: {
	snap: RosterChangeSnapshot;
	threshold: number;
	totalMembers: number;
	onClick: () => void;
}) {
	const approvals = snap.account.approvalCount;
	const ratio = threshold === 0 ? 1 : Math.min(1, approvals / threshold);
	const reached = approvals >= threshold;
	const removed = snap.account.removals.length;
	const added = snap.account.additions.length;
	const postCount = totalMembers - removed + added;
	const newThr = snap.account.hasNewThreshold
		? snap.account.newThreshold.toString()
		: threshold.toString();
	return (
		<button
			type="button"
			onClick={onClick}
			className="text-left surface-raised border border-border rounded-[var(--radius-card)] p-5 hover:border-border-strong hover:bg-surface-3 transition-colors group cursor-pointer w-full"
		>
			<div className="flex items-baseline justify-between gap-2 mb-3">
				<span className="font-display text-[28px] tabular text-text leading-[1] inline-flex items-center gap-2">
					<UserMinus className="h-4 w-4 text-text-3" />#{snap.index}
				</span>
				<span className="smallcaps text-text-3 inline-flex items-center gap-1">
					<Trash2 className="h-3 w-3" />
					{removed} removed{added > 0 && ` · ${added} added`}
				</span>
			</div>

			<div className="flex items-baseline gap-2 mb-3 font-mono text-[12.5px] tabular text-text-2">
				<span>
					{newThr} of {postCount}
				</span>
				<span className="text-text-4">·</span>
				<span className="text-text-3">
					was {threshold} of {totalMembers}
				</span>
			</div>

			<div className="flex items-baseline gap-2 mb-3">
				<span
					className={cn(
						'font-display text-[36px] leading-[0.9] tabular',
						reached ? 'text-sage' : 'text-text',
					)}
				>
					{approvals}
				</span>
				<span className="font-display italic text-text-3 text-[14px] tracking-tight">of</span>
				<span className="font-display text-[36px] leading-[0.9] tabular text-text-2">
					{threshold}
				</span>
				<span className="ml-auto smallcaps inline-flex items-center gap-1.5 text-text-3 group-hover:text-text">
					{reached ? (
						<>
							<Check className="h-3 w-3 text-sage" />
							Quorum
						</>
					) : (
						<>
							<Loader2 className="h-3 w-3" />
							Awaiting
						</>
					)}
				</span>
			</div>

			<div className="h-1 w-full bg-surface-3 rounded overflow-hidden mb-1">
				<div
					className={cn('h-full transition-all duration-500', reached ? 'bg-sage' : 'bg-clay')}
					style={{ width: `${ratio * 100}%` }}
				/>
			</div>
		</button>
	);
}

function DwalletBalanceCard({ vault }: { vault: VaultState }) {
	const sol = vault.dwalletBalance / 1e9;
	const low = vault.dwalletBalance < FUND_THRESHOLD_LAMPORTS;
	const dwalletPda = dwalletPdaFor(vault.account);
	const [copied, setCopied] = React.useState(false);

	function copy() {
		void navigator.clipboard.writeText(vault.dwalletPubkey.toBase58()).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1400);
		});
	}

	return (
		<Card tone="raised" className="p-0 overflow-hidden">
			<SectionHead
				label="dWallet balance"
				right={
					<span className="smallcaps text-text-4">
						{truncateAddress(dwalletPda.toBase58(), 4, 4)} (PDA)
					</span>
				}
			/>
			<div className="px-5 sm:px-8 py-5 sm:py-6 flex items-baseline gap-3">
				<span
					className={cn(
						'font-display text-[44px] sm:text-[60px] leading-[0.9] tabular',
						low ? 'text-clay' : 'text-text',
					)}
				>
					{sol.toFixed(sol < 1 ? 4 : 2)}
				</span>
				<span className="smallcaps text-text-3">SOL</span>
			</div>
			<p className="px-5 sm:px-8 text-[12.5px] text-text-3 leading-[1.55]">
				{low
					? 'Top up the dWallet pubkey before any sweep — Solana ixs need fee SOL on the source.'
					: 'Healthy. Sweeps will pay their own fees from this balance.'}
			</p>
			<div className="px-5 sm:px-8 pb-5 pt-3 flex flex-wrap items-center gap-2">
				<Button variant="secondary" size="sm" onClick={copy}>
					{copied ? (
						<>
							<Check className="h-3 w-3 text-sage" />
							<span className="text-sage">Copied dWallet</span>
						</>
					) : (
						<>
							<Copy className="h-3 w-3" />
							Copy dWallet address
						</>
					)}
				</Button>
				{low && (
					<Button variant="ghost" size="sm" asChild>
						<a href="https://faucet.solana.com/" target="_blank" rel="noopener noreferrer">
							<ExternalLink className="h-3 w-3" />
							Devnet faucet
						</a>
					</Button>
				)}
			</div>
		</Card>
	);
}

function SectionHead({ label, right }: { label: string; right?: React.ReactNode }) {
	return (
		<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
			<span className="smallcaps text-text-3">{label}</span>
			{right}
		</div>
	);
}

function MemberRow({ slot, isMe }: { slot: Uint8Array; isMe: boolean }) {
	const [copied, setCopied] = React.useState(false);
	const scheme = slot[0] ?? 0xff;
	const idBytes = memberIdBytes(slot);
	const idHex = bytesToHex(idBytes.slice(1));
	const display = displayForSlot(scheme, idBytes.slice(1));
	const subtitle = subtitleForScheme(scheme);
	const Icon = scheme === SCHEME_WEBAUTHN ? Fingerprint : Wallet;

	function copy() {
		void navigator.clipboard.writeText(display).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1400);
		});
	}

	return (
		<li className="px-5 sm:px-6 py-3.5 flex items-center gap-3">
			<div
				className={cn(
					'h-8 w-8 flex-none rounded border flex items-center justify-center',
					isMe ? 'border-sage/50 bg-sage/10' : 'border-border',
				)}
			>
				<Icon className={cn('h-3.5 w-3.5', isMe ? 'text-sage' : 'text-text-3')} />
			</div>
			<div className="flex-1 min-w-0">
				<div className="font-mono text-[12.5px] tabular text-text truncate">{display}</div>
				<div className="mt-0.5 smallcaps text-text-3 inline-flex items-center gap-2">
					<span>{subtitle}</span>
					{isMe && <span className="text-sage">· You</span>}
					{scheme !== SCHEME_SOLANA_ADDRESS && scheme !== SCHEME_WEBAUTHN && (
						<span className="text-text-4 truncate max-w-[160px]" title={`hex: ${idHex}`}>
							{/* preserved hex available on hover */}
						</span>
					)}
				</div>
			</div>
			<button
				type="button"
				onClick={copy}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1 flex-none"
				aria-label="Copy member id"
			>
				{copied ? <Check className="h-3 w-3 text-sage" /> : <Copy className="h-3 w-3" />}
				<span className="hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
			</button>
		</li>
	);
}

function VaultSkeleton({ recoveryId }: { recoveryId: string }) {
	return (
		<>
			<div className="mb-8 flex items-center justify-between">
				<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<ArrowLeft className="h-3 w-3" />
					Directory
				</span>
				<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<Loader2 className="h-3 w-3 animate-spin" />
					Reading devnet
				</span>
			</div>
			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-6 sm:px-10 pt-6 sm:pt-8 pb-2 flex items-baseline justify-between border-b border-border">
					<span className="smallcaps text-text-3">Recovery PDA</span>
				</div>
				<div className="px-6 sm:px-10 py-6 sm:py-8">
					<div
						className="font-display tracking-[-0.018em] tabular break-all text-clay text-[24px] sm:text-[36px] lg:text-[48px] leading-[1.04]"
						style={{ fontVariantLigatures: 'none' }}
					>
						{recoveryId}
					</div>
				</div>
				<div className="rule-h" />
				<div className="px-6 sm:px-10 pt-5 pb-2 flex items-baseline justify-between border-t border-border">
					<span className="smallcaps text-text-3">dWallet pubkey</span>
				</div>
				<div className="px-6 sm:px-10 py-6 sm:py-8">
					<div className="h-7 sm:h-9 w-2/3 max-w-[520px] bg-surface-3 rounded animate-pulse" />
				</div>
			</Card>
		</>
	);
}

function BlockId({
	value,
	big,
	accent,
}: {
	value: string;
	big?: boolean;
	accent: 'clay' | 'text';
}) {
	const [copied, setCopied] = React.useState(false);
	function copy() {
		void navigator.clipboard.writeText(value).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1600);
		});
	}
	return (
		<div className="px-5 sm:px-10 py-5 sm:py-8 flex flex-col sm:flex-row items-stretch sm:items-start gap-3 sm:gap-5">
			<div className="flex-1 min-w-0">
				<div
					className={cn(
						'font-display tracking-[-0.018em] tabular break-all',
						big
							? 'text-[20px] sm:text-[36px] lg:text-[48px] leading-[1.06]'
							: 'text-[14px] sm:text-[22px] lg:text-[28px] leading-[1.12]',
						accent === 'clay' ? 'text-clay' : 'text-text',
					)}
					style={{ fontVariantLigatures: 'none' }}
				>
					{value}
				</div>
			</div>
			<div className="flex-none sm:mt-1 flex items-center justify-end gap-3">
				<a
					href={`${SOLSCAN_BASE}/account/${value}${SOLSCAN_CLUSTER}`}
					target="_blank"
					rel="noopener noreferrer"
					className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1"
				>
					<ExternalLink className="h-3 w-3" />
					Explorer
				</a>
				<button
					type="button"
					onClick={copy}
					className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1"
					aria-label="Copy"
				>
					{copied ? <Check className="h-3 w-3 text-sage" /> : <Copy className="h-3 w-3" />}
					{copied ? 'Copied' : 'Copy'}
				</button>
			</div>
		</div>
	);
}

function memberSlotMatchesAddress(slot: Uint8Array, address: string): boolean {
	if (slot[0] !== SCHEME_SOLANA_ADDRESS) return false;
	const idBytes = memberIdBytes(slot).slice(1);
	if (idBytes.length !== 32) return false;
	try {
		return new PublicKey(idBytes).toBase58() === address;
	} catch {
		return false;
	}
}

function displayForSlot(scheme: number, id: Uint8Array): string {
	if (scheme === SCHEME_SOLANA_ADDRESS && id.length === 32) {
		try {
			return new PublicKey(id).toBase58();
		} catch {
			return bytesToHex(id);
		}
	}
	return bytesToHex(id);
}

function subtitleForScheme(scheme: number): string {
	switch (scheme) {
		case SCHEME_SOLANA_ADDRESS:
			return 'Solana wallet';
		case SCHEME_ED25519:
			return 'Ed25519 pubkey';
		case SCHEME_SECP256K1:
			return 'Secp256k1 pubkey';
		case SCHEME_SECP256R1:
			return 'Secp256r1 pubkey';
		case SCHEME_WEBAUTHN:
			return 'WebAuthn passkey';
		default:
			return `Scheme ${scheme}`;
	}
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function bundleSummary(b: SweepBundle): string {
	const sweepLamports = BigInt(b.solBalanceLamports) - BigInt(b.feeReserveLamports);
	const sol = `${(Number(sweepLamports) / 1e9).toFixed(6)} SOL`;
	if (b.tokenAccounts.length === 0) return sol;
	return `${sol} + ${b.tokenAccounts.length} SPL`;
}
