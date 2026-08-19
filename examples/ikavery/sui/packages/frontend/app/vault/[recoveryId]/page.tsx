'use client';

import { Button, Card, cn, ProposalCardSkeleton } from '@fesal-packages/ikavery-frontend-ui';
import {
	listEnrollmentSnapshots,
	listRosterChangeSnapshots,
	type EnrollmentSnapshot,
	type ProposalSnapshot,
	type RosterChangeSnapshot,
} from '@fesal-packages/ikavery-sui-sdk';
import { useCurrentAccount } from '@mysten/dapp-kit-react';
import { fromHex, normalizeSuiAddress } from '@mysten/sui/utils';
import { useQuery } from '@tanstack/react-query';
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

import { ReplenishButton } from '@/components/vault/replenish-button';
import { env } from '@/lib/env';
import { bytesToHex } from '@/lib/format';
import { listProposalSnapshots } from '@/lib/proposals';
import { buildRecoveryClient } from '@/lib/recovery-client';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import { explorerObjectUrl, findMember, vaultMemberCount } from '@/lib/recovery-state';
import { hexToBytes, loadActiveImporter, type CachedImporter } from '@/lib/storage';
import { useVaultQuery } from '@/lib/use-vault';

// Below this many presigns the meter highlights — every recovery proposal
// consumes one per Solana tx in the sweep, so a thin pool stalls signatures.
const PRESIGN_LOW_WATER = 3;

export default function VaultDashboard() {
	const params = useParams<{ recoveryId: string }>();
	const recoveryId = params.recoveryId;
	const router = useRouter();
	const { suiClient } = useRecoveryClient();
	const account = useCurrentAccount();

	const state = useVaultQuery(recoveryId);

	// Pull the cached importer so passkey access shows up on the dashboard
	// even when no wallet is connected. A passkey member can act on the vault
	// by signing the WebAuthn challenge directly — no Sui currentAccount needed
	// beyond a separate gas payer.
	const [cachedImporter, setCachedImporter] = React.useState<CachedImporter | null>(null);
	React.useEffect(() => {
		void loadActiveImporter().then(setCachedImporter);
	}, []);

	// Proposals: enumerate 0..nextProposalId-1 and fetch snapshots. Refetch
	// alongside the vault state so approval counts stay fresh.
	const proposals = useQuery({
		queryKey: [
			'proposals',
			recoveryId,
			state.data?.nextProposalId.toString() ?? '_',
			suiClient ? 'ready' : '_',
		],
		enabled: !!suiClient && !!state.data && Number(state.data.nextProposalId) > 0,
		queryFn: () => listProposalSnapshots(suiClient!, state.data!),
		refetchInterval: 8000,
		staleTime: 4000,
	});

	const enrollments = useQuery({
		queryKey: [
			'enrollments',
			recoveryId,
			state.data?.nextEnrollmentId.toString() ?? '_',
			suiClient ? 'ready' : '_',
		],
		enabled: !!suiClient && !!state.data && Number(state.data.nextEnrollmentId) > 0,
		queryFn: async (): Promise<EnrollmentSnapshot[]> => {
			const recClient = buildRecoveryClient(suiClient!, recoveryId);
			return await listEnrollmentSnapshots(recClient);
		},
		refetchInterval: 8000,
		staleTime: 4000,
	});

	const rosterChanges = useQuery({
		queryKey: [
			'roster-changes',
			recoveryId,
			state.data?.nextRosterChangeId.toString() ?? '_',
			suiClient ? 'ready' : '_',
		],
		enabled: !!suiClient && !!state.data && Number(state.data.nextRosterChangeId) > 0,
		queryFn: async (): Promise<RosterChangeSnapshot[]> => {
			const recClient = buildRecoveryClient(suiClient!, recoveryId);
			return await listRosterChangeSnapshots(recClient);
		},
		refetchInterval: 8000,
		staleTime: 4000,
	});

	if (state.isLoading) {
		return <VaultSkeleton recoveryId={recoveryId} />;
	}

	if (state.error) {
		return (
			<div className="max-w-[640px] mx-auto py-16">
				<button
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
								The recovery id may be wrong, or the object lives on a different network. Check that
								you&apos;re on <span className="font-mono">{env.network}</span> and try again.
							</p>
							<div className="mt-3 font-mono text-[11px] tabular text-text-3 break-all">
								{String(state.error instanceof Error ? state.error.message : state.error)}
							</div>
						</div>
					</div>
				</Card>
			</div>
		);
	}

	if (!state.data) return null;
	const vault = state.data;
	const total = vaultMemberCount(vault);
	const meAsWalletMember =
		account &&
		findMember(
			vault,
			inferWalletScheme(cachedImporter, account.address, new Uint8Array(account.publicKey)),
			new Uint8Array(account.publicKey),
		);
	const meAsApproverMember =
		account &&
		findMember(vault, 'sender_address', fromHex(normalizeSuiAddress(account.address).slice(2)));
	const meAsPasskeyMember =
		cachedImporter && cachedImporter.kind === 'passkey'
			? findMember(vault, 'webauthn', hexToBytes(cachedImporter.publicKeyHex))
			: null;
	const isMember = !!meAsWalletMember || !!meAsApproverMember || !!meAsPasskeyMember;

	return (
		<>
			{/* Top breadcrumb */}
			<div className="mb-8 flex items-center justify-between">
				<button
					onClick={() => router.push('/vault')}
					className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5"
				>
					<ArrowLeft className="h-3 w-3" />
					Directory
				</button>
				<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<span className="h-1.5 w-1.5 rounded-full bg-sage" />
					Active on {env.network}
				</div>
			</div>

			{/* Block-printed Recovery ID */}
			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-10 pt-5 sm:pt-8 pb-2 flex items-baseline justify-between border-b border-border">
					<span className="smallcaps text-text-3">Recovery ID</span>
					<span className="smallcaps text-text-4">v{shortPkg(env.recoveryPackageId)}</span>
				</div>
				<BlockId value={vault.recoveryId} accent="clay" big />
				<div className="rule-h" />
				<div className="px-5 sm:px-10 pt-5 pb-2 flex items-baseline justify-between border-t border-border">
					<span className="smallcaps text-text-3">dWallet ID</span>
					<span className="smallcaps text-text-4">Ika 2PC-MPC</span>
				</div>
				<BlockId value={vault.dwalletId} accent="text" />
			</Card>

			{/* Three-column ledger */}
			<div className="mt-4 grid grid-cols-1 lg:grid-cols-12 gap-4">
				{/* Members + threshold */}
				<Card tone="raised" className="lg:col-span-7 p-0 overflow-hidden">
					<SectionHead
						label="Members"
						right={<span className="font-mono text-[12px] text-text-3 tabular">{total} total</span>}
					/>
					<ul className="divide-y divide-border">
						{vault.members.map((m, i) => (
							<MemberRow
								key={`m:${i}:${bytesToHex(m.publicKey)}`}
								scheme={m.scheme}
								identity={bytesToHex(m.publicKey)}
								isMe={
									(meAsWalletMember != null && m.id === meAsWalletMember.id) ||
									(meAsApproverMember != null && m.id === meAsApproverMember.id) ||
									(meAsPasskeyMember != null && m.id === meAsPasskeyMember.id)
								}
							/>
						))}
					</ul>
				</Card>

				{/* Threshold + presign pool */}
				<div className="lg:col-span-5 grid grid-cols-1 gap-4">
					<Card tone="raised" className="p-0 overflow-hidden">
						<SectionHead label="Threshold" />
						<div className="px-5 sm:px-8 py-6 sm:py-7 flex items-baseline gap-2 sm:gap-3">
							<span className="font-display text-[52px] sm:text-[80px] leading-[0.9] tabular text-text">
								{vault.threshold}
							</span>
							<span className="font-display italic text-text-3 text-[20px] sm:text-[26px] tracking-tight">
								of
							</span>
							<span className="font-display text-[52px] sm:text-[80px] leading-[0.9] tabular text-text-2">
								{total}
							</span>
						</div>
						<p className="px-5 sm:px-8 pb-5 text-[12.5px] text-text-3 leading-[1.55]">
							Recovery requires this many approvals. Members below the threshold cannot move funds
							alone.
						</p>
					</Card>

					<Card tone="raised" className="p-0 overflow-visible">
						<SectionHead label="Presign pool" />
						<div className="px-5 sm:px-8 py-5 sm:py-6 flex items-baseline gap-3">
							<span
								className={cn(
									'font-display text-[48px] sm:text-[64px] leading-[0.9] tabular',
									vault.presignCount < PRESIGN_LOW_WATER ? 'text-clay' : 'text-text',
								)}
							>
								{vault.presignCount}
							</span>
							<span className="smallcaps text-text-3">ready</span>
						</div>
						<p className="px-5 sm:px-8 text-[12.5px] text-text-3 leading-[1.55]">
							{vault.presignCount === 0
								? 'Replenish before proposing. Each tx in a sweep consumes one.'
								: vault.presignCount < PRESIGN_LOW_WATER
									? 'Pool is thin. Replenish before sweeping a multi-tx bundle.'
									: 'Healthy. Each Solana tx in a sweep consumes one presign.'}
						</p>
						<div className="px-5 sm:px-8 pb-5 pt-3">
							<ReplenishButton
								recoveryId={recoveryId}
								suggestedCount={Math.max(
									PRESIGN_LOW_WATER,
									PRESIGN_LOW_WATER + 2 - vault.presignCount,
								)}
								compact={vault.presignCount >= PRESIGN_LOW_WATER}
							/>
						</div>
					</Card>
				</div>
			</div>

			{/* Membership + actions */}
			<Card
				tone="raised"
				className="mt-4 px-5 sm:px-6 py-5 flex flex-col md:flex-row md:items-center gap-4"
			>
				<div className="flex items-start gap-3 sm:gap-4 flex-1 min-w-0">
					<div className="h-9 w-9 flex-none rounded border border-border flex items-center justify-center">
						{isMember ? (
							<ShieldCheck className="h-3.5 w-3.5 text-sage" />
						) : (
							<Wallet className="h-3.5 w-3.5 text-text-3" />
						)}
					</div>
					<div className="flex-1 min-w-0">
						<div className="smallcaps text-text-3">Your access</div>
						<p className="mt-1 text-[13.5px] text-text-2 leading-[1.55]">
							{meAsWalletMember
								? 'This wallet is a member. You can propose recoveries, approve proposals, and enroll new devices.'
								: meAsApproverMember
									? "This wallet is an approver-only member. You can propose and approve, but you can't execute proposals or be re-encrypted to during enrollment."
									: meAsPasskeyMember
										? 'A passkey on this device matches a member. Connect any wallet for gas, then propose, approve, or enroll.'
										: !account
											? "No access detected on this device. Connect a wallet that's in the member set, or open the vault on the device that holds the passkey."
											: "Your wallet is not in the member set, and no matching passkey was found on this device. You can read the vault state but can't act on it from here."}
						</p>
					</div>
				</div>
				<div className="grid grid-cols-2 sm:flex sm:flex-wrap items-stretch sm:items-center gap-2 md:flex-none">
					<Button
						variant="irreversible"
						size="default"
						disabled={!isMember}
						onClick={() => router.push(`/vault/${recoveryId}/recover`)}
						className="col-span-2"
					>
						<KeyRound className="h-3.5 w-3.5" />
						Recover funds
					</Button>
					<Button
						variant="secondary"
						size="default"
						disabled={!isMember}
						onClick={() => router.push(`/vault/${recoveryId}/enroll`)}
					>
						<UserPlus className="h-3.5 w-3.5" />
						Add device
					</Button>
					<Button
						variant="secondary"
						size="default"
						disabled={!isMember}
						onClick={() => router.push(`/vault/${recoveryId}/roster`)}
					>
						<UserMinus className="h-3.5 w-3.5" />
						Edit roster
					</Button>
					<a
						href={explorerObjectUrl(recoveryId)}
						target="_blank"
						rel="noopener noreferrer"
						className="col-span-2 sm:col-span-1 inline-flex items-center justify-center sm:justify-start gap-1.5 smallcaps text-text-3 hover:text-text py-1"
					>
						<ArrowUpRight className="h-3 w-3" />
						Explorer
					</a>
				</div>
			</Card>

			{/* Active enrollments */}
			{enrollments.data?.some((e) => !e.executed) && (
				<section className="mt-10">
					<header className="mb-3 flex items-baseline justify-between">
						<div className="smallcaps text-text-3">Active enrollments</div>
						<span className="font-mono text-[12px] text-text-3 tabular">
							{enrollments.data.filter((e) => !e.executed).length} pending
						</span>
					</header>
					<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
						{enrollments.data
							.filter((e) => !e.executed)
							.map((e) => (
								<EnrollmentCard
									key={e.enrollmentId.toString()}
									snap={e}
									threshold={vault.threshold}
									onClick={() =>
										router.push(`/vault/${recoveryId}/enroll/${e.enrollmentId.toString()}`)
									}
								/>
							))}
					</div>
				</section>
			)}

			{/* Active roster changes */}
			{rosterChanges.data?.some((r) => !r.executed) && (
				<section className="mt-10">
					<header className="mb-3 flex items-baseline justify-between">
						<div className="smallcaps text-text-3">Active roster changes</div>
						<span className="font-mono text-[12px] text-text-3 tabular">
							{rosterChanges.data.filter((r) => !r.executed).length} pending
						</span>
					</header>
					<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
						{rosterChanges.data
							.filter((r) => !r.executed)
							.map((r) => (
								<RosterChangeCard
									key={r.rosterChangeId.toString()}
									snap={r}
									threshold={vault.threshold}
									totalMembers={vault.members.length}
									onClick={() =>
										router.push(`/vault/${recoveryId}/roster/${r.rosterChangeId.toString()}`)
									}
								/>
							))}
					</div>
				</section>
			)}

			{/* Recovery proposals */}
			<section className="mt-10">
				<header className="mb-3 flex items-baseline justify-between">
					<div className="smallcaps text-text-3">Recovery proposals</div>
					{proposals.data && proposals.data.length > 0 && (
						<span className="font-mono text-[12px] text-text-3 tabular">
							{proposals.data.length} on record
						</span>
					)}
				</header>
				{Number(vault.nextProposalId) === 0 ? (
					<Card tone="raised" className="px-5 sm:px-6 py-6 sm:py-7">
						<p className="text-[14px] text-text-2 leading-[1.55]">
							No recovery proposals yet. Initiate a sweep from{' '}
							<button
								onClick={() => router.push(`/vault/${recoveryId}/recover`)}
								className="text-clay hover:text-text underline-offset-2 hover:underline"
							>
								Recover funds
							</button>{' '}
							when you need to move funds out.
						</p>
					</Card>
				) : proposals.isLoading ? (
					<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
						<ProposalCardSkeleton />
						<ProposalCardSkeleton />
					</div>
				) : (
					<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
						{(proposals.data ?? []).map((p) => (
							<ProposalCard
								key={p.proposalId.toString()}
								snap={p}
								onClick={() =>
									router.push(`/vault/${recoveryId}/proposal/${p.proposalId.toString()}`)
								}
							/>
						))}
					</div>
				)}
			</section>
		</>
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

function MemberRow({
	scheme,
	identity,
	isMe,
}: {
	scheme: import('@/lib/recovery-state').Scheme;
	identity: string;
	isMe: boolean;
}) {
	const [copied, setCopied] = React.useState(false);
	const Icon = scheme === 'webauthn' ? Fingerprint : Wallet;
	const subtitle =
		scheme === 'webauthn'
			? 'Passkey · secp256r1 pubkey'
			: scheme === 'sender_address'
				? 'Approver-only · Sui address'
				: `Wallet · ${scheme}`;
	const display = scheme === 'sender_address' ? `0x${identity}` : identity;
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
					{isMe && <span className="text-sage">· Connected</span>}
				</div>
			</div>
			<button
				type="button"
				onClick={() => {
					void navigator.clipboard.writeText(display).then(() => {
						setCopied(true);
						setTimeout(() => setCopied(false), 1400);
					});
				}}
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
					Reading {env.network}
				</span>
			</div>
			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-6 sm:px-10 pt-6 sm:pt-8 pb-2 flex items-baseline justify-between border-b border-border">
					<span className="smallcaps text-text-3">Recovery ID</span>
					<span className="smallcaps text-text-4">v{shortPkg(env.recoveryPackageId)}</span>
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
					<span className="smallcaps text-text-3">dWallet ID</span>
					<span className="smallcaps text-text-4">Ika 2PC-MPC</span>
				</div>
				<div className="px-6 sm:px-10 py-6 sm:py-8">
					<div className="h-7 sm:h-9 w-2/3 max-w-[520px] bg-surface-3 rounded animate-pulse" />
				</div>
			</Card>
			<div className="mt-4 grid grid-cols-1 lg:grid-cols-12 gap-4">
				<Card tone="raised" className="lg:col-span-7 p-0 overflow-hidden">
					<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
						<span className="smallcaps text-text-3">Members</span>
						<span className="font-mono text-[12px] text-text-4 tabular">…</span>
					</div>
					<ul className="divide-y divide-border">
						{[0, 1, 2].map((i) => (
							<li key={i} className="px-5 sm:px-6 py-3.5 flex items-center gap-3">
								<div className="h-8 w-8 flex-none rounded border border-border" />
								<div className="flex-1 min-w-0 space-y-1.5">
									<div className="h-3.5 w-2/3 max-w-[420px] bg-surface-3 rounded animate-pulse" />
									<div className="h-2.5 w-24 bg-surface-3 rounded animate-pulse" />
								</div>
							</li>
						))}
					</ul>
				</Card>
				<div className="lg:col-span-5 grid grid-cols-1 gap-4">
					<Card tone="raised" className="p-0 overflow-hidden">
						<div className="px-5 sm:px-8 py-3 border-b border-border">
							<span className="smallcaps text-text-3">Threshold</span>
						</div>
						<div className="px-5 sm:px-8 py-7">
							<div className="h-14 w-32 bg-surface-3 rounded animate-pulse" />
						</div>
					</Card>
					<Card tone="raised" className="p-0 overflow-hidden">
						<div className="px-5 sm:px-8 py-3 border-b border-border">
							<span className="smallcaps text-text-3">Presign pool</span>
						</div>
						<div className="px-5 sm:px-8 py-6">
							<div className="h-12 w-20 bg-surface-3 rounded animate-pulse" />
						</div>
					</Card>
				</div>
			</div>
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
					href={explorerObjectUrl(value)}
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

function shortPkg(pkg: string): string {
	return `${pkg.slice(0, 6)}…${pkg.slice(-4)}`;
}

function ProposalCard({ snap, onClick }: { snap: ProposalSnapshot; onClick: () => void }) {
	const approvals = Number(snap.approvals);
	const threshold = Number(snap.threshold);
	const ratio = threshold === 0 ? 1 : Math.min(1, approvals / threshold);
	const reached = approvals >= threshold;
	return (
		<button
			type="button"
			onClick={onClick}
			className="text-left surface-raised border border-border rounded-[var(--radius-card)] p-5 hover:border-border-strong hover:bg-surface-3 transition-colors group cursor-pointer w-full"
		>
			<div className="flex items-baseline justify-between gap-2 mb-3">
				<span className="font-display text-[28px] tabular text-text leading-[1]">
					#{snap.proposalId.toString()}
				</span>
				<span
					className={cn(
						'smallcaps inline-flex items-center gap-1.5',
						snap.executed ? 'text-text-3' : reached ? 'text-sage' : 'text-clay',
					)}
				>
					{snap.executed ? (
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
				<span className="ml-auto smallcaps text-text-3">{snap.preview.txCount} tx</span>
			</div>

			<div className="h-1 w-full bg-surface-3 rounded overflow-hidden mb-3">
				<div
					className={cn('h-full transition-all duration-500', reached ? 'bg-sage' : 'bg-clay')}
					style={{ width: `${ratio * 100}%` }}
				/>
			</div>

			<div className="flex items-center justify-between gap-2">
				<span className="text-[12.5px] text-text-3 leading-[1.5]">
					{(Number(snap.preview.totalLamportsTransferred) / 1e9).toFixed(6)} SOL
					{snap.preview.totalSplTransferred.length > 0 &&
						` · ${snap.preview.totalSplTransferred.length} SPL`}
				</span>
				<span
					className={cn(
						'smallcaps inline-flex items-center gap-1 transition-colors',
						snap.executed
							? 'text-text-3 group-hover:text-text-2'
							: 'text-clay group-hover:text-text',
					)}
				>
					{snap.executed ? 'View' : 'Open'}
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
	const approvals = Number(snap.approvals);
	const ratio = threshold === 0 ? 1 : Math.min(1, approvals / threshold);
	const reached = approvals >= threshold;
	const kindLabel =
		snap.newMember.kind === 'sender_address'
			? 'Approver-only'
			: snap.newMember.kind === 'webauthn'
				? 'Passkey'
				: `Wallet · ${snap.newMember.kind}`;
	const identity =
		snap.newMember.kind === 'sender_address'
			? snap.newMember.address
			: `0x${bytesToHex(snap.newMember.publicKey)}`;
	return (
		<button
			type="button"
			onClick={onClick}
			className="text-left surface-raised border border-border rounded-[var(--radius-card)] p-5 hover:border-border-strong hover:bg-surface-3 transition-colors group cursor-pointer w-full"
		>
			<div className="flex items-baseline justify-between gap-2 mb-3">
				<span className="font-display text-[28px] tabular text-text leading-[1] inline-flex items-center gap-2">
					<UserPlus className="h-4 w-4 text-text-3" />#{snap.enrollmentId.toString()}
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
	const approvals = Number(snap.approvals);
	const ratio = threshold === 0 ? 1 : Math.min(1, approvals / threshold);
	const reached = approvals >= threshold;
	const removed = snap.membersToRemove.length;
	const postCount = totalMembers - removed;
	const newThr = snap.newThreshold !== null ? snap.newThreshold.toString() : threshold;
	return (
		<button
			type="button"
			onClick={onClick}
			className="text-left surface-raised border border-border rounded-[var(--radius-card)] p-5 hover:border-border-strong hover:bg-surface-3 transition-colors group cursor-pointer w-full"
		>
			<div className="flex items-baseline justify-between gap-2 mb-3">
				<span className="font-display text-[28px] tabular text-text leading-[1] inline-flex items-center gap-2">
					<UserMinus className="h-4 w-4 text-text-3" />#{snap.rosterChangeId.toString()}
				</span>
				<span className="smallcaps text-text-3 inline-flex items-center gap-1">
					<Trash2 className="h-3 w-3" />
					{removed} removed
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

/**
 * Best-effort scheme inference for a connected wallet account. The wallet
 * standard exposes a raw `publicKey` but no scheme tag, so:
 *   - 32 bytes ⇒ ed25519
 *   - 33 bytes ⇒ secp256k1 (and we let the on-chain match disambiguate from r1)
 * If the cached importer matches this exact account, prefer its stored scheme.
 */
function inferWalletScheme(
	cachedImporter: CachedImporter | null,
	address: string,
	publicKey: Uint8Array,
): import('@/lib/recovery-state').Scheme {
	if (
		cachedImporter?.kind === 'wallet' &&
		cachedImporter.address.toLowerCase() === address.toLowerCase()
	) {
		return cachedImporter.scheme;
	}
	if (publicKey.length === 32) return 'ed25519';
	return 'secp256k1';
}
