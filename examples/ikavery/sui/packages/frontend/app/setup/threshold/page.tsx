'use client';

import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import type { UiWallet, UiWalletAccount } from '@mysten/dapp-kit-core';
import { useCurrentAccount, useWalletConnection, useWallets } from '@mysten/dapp-kit-react';
import { isEnokiWallet } from '@mysten/enoki';
import {
	AlertCircle,
	ArrowLeft,
	ArrowRight,
	Check,
	Fingerprint,
	Loader2,
	Plus,
	Trash2,
	Wallet,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import { WalletConnect } from '@/components/wallet-connect';
import { dAppKit } from '@/lib/dapp-kit';
import { capturePasskeyMember, captureWalletMember } from '@/lib/member-identity';
import { sameIdentity, useSetup, type StoredMember } from '@/store/setup';

import { FieldLabel, Mono, StepFooter, StepHeader } from '../_parts';

export default function ThresholdStep() {
	const router = useRouter();
	const importer = useSetup((s) => s.importer);
	const members = useSetup((s) => s.members);
	const setMembers = useSetup((s) => s.setMembers);
	const threshold = useSetup((s) => s.threshold);
	const setThreshold = useSetup((s) => s.setThreshold);
	const gasPayer = useCurrentAccount();
	const { isConnecting: walletReconnecting } = useWalletConnection();

	React.useEffect(() => {
		if (!importer) router.replace('/setup/connect');
	}, [importer, router]);

	if (!importer) return null;

	const N = members.length;
	const validThreshold = Math.max(1, Math.min(N, threshold));

	function addMember(m: StoredMember): { ok: true } | { ok: false; reason: string } {
		for (const existing of members) {
			if (sameIdentity(existing, m)) {
				return {
					ok: false,
					reason:
						m.kind === 'passkey'
							? 'That passkey is already in the roster.'
							: 'That wallet is already in the roster.',
				};
			}
		}
		setMembers([...members, m]);
		return { ok: true };
	}

	function removeMember(idx: number) {
		const target = members[idx];
		if (!target || !importer) return;
		// The importer is locked into the roster — the protocol requires them at
		// index 0. They can switch identities from /setup/connect.
		if (sameIdentity(target, importer)) return;
		const next = members.filter((_, i) => i !== idx);
		setMembers(next);
		if (threshold > next.length) setThreshold(next.length);
	}

	return (
		<>
			<StepHeader
				ord="02 / Quorum"
				title="Pick a threshold"
				italic="and a roster."
				hint="A threshold is the minimum number of members that must approve a recovery. Each member produces their encryption identity right here in this session — passkey (this device, a phone, a hardware key) or any Sui wallet."
			/>

			{gasPayer ? (
				<GasPayerBanner address={gasPayer.address} />
			) : (
				<NoGasPayerBanner reconnecting={walletReconnecting} />
			)}

			<div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
				<Card tone="raised" className="lg:col-span-5 p-5 sm:p-8">
					<div className="flex items-baseline justify-between mb-2">
						<FieldLabel>Threshold</FieldLabel>
						<span className="smallcaps text-text-3">k of {N}</span>
					</div>
					<div className="font-display text-[64px] sm:text-[112px] leading-none tabular text-text">
						{validThreshold}
						<span className="text-text-3"> /{N}</span>
					</div>
					<input
						type="range"
						min={1}
						max={N}
						value={validThreshold}
						onChange={(e) => setThreshold(parseInt(e.target.value, 10))}
						className="w-full mt-6 h-1 bg-surface-3 rounded-full appearance-none cursor-pointer accent-clay"
					/>
					<div className="flex justify-between mt-2 smallcaps text-text-4">
						<span>1</span>
						<span>{N}</span>
					</div>
					<div
						className="mt-6 grid gap-1.5"
						style={{ gridTemplateColumns: `repeat(${N}, minmax(0, 1fr))` }}
					>
						{Array.from({ length: N }).map((_, i) => (
							<span
								key={i}
								className={`h-1.5 rounded-full ${i < validThreshold ? 'bg-clay' : 'bg-surface-3'}`}
							/>
						))}
					</div>
					<p className="mt-6 text-[13px] text-text-3 leading-[1.55]">
						<span className="text-text">{validThreshold}</span> of your{' '}
						<span className="text-text">{N}</span> members will need to approve a recovery. Higher
						numbers are safer; lower numbers are faster to invoke under stress.
					</p>
				</Card>

				<Card tone="raised" className="lg:col-span-7 p-6 sm:p-8">
					<div className="flex items-center justify-between mb-4">
						<FieldLabel>Roster</FieldLabel>
						<span className="smallcaps text-text-3">
							{N} member{N === 1 ? '' : 's'}
						</span>
					</div>
					<ul className="space-y-2.5">
						{members.map((m, i) => (
							<MemberRow
								key={i}
								idx={i}
								isImporter={sameIdentity(m, importer)}
								member={m}
								onRemove={() => removeMember(i)}
							/>
						))}
					</ul>

					<AddMemberPanel onAdd={addMember} />
				</Card>
			</div>

			<StepFooter
				hint={`Recovery will require ${validThreshold} approval${validThreshold === 1 ? '' : 's'} from this roster.`}
				back={
					<Button variant="ghost" size="default" onClick={() => router.push('/setup/connect')}>
						<ArrowLeft className="h-3.5 w-3.5" /> Back
					</Button>
				}
				next={
					<Button
						variant="primary"
						size="lg"
						disabled={N < 1 || validThreshold < 1}
						onClick={() => {
							if (threshold !== validThreshold) setThreshold(validThreshold);
							router.push('/setup/key');
						}}
					>
						Continue <ArrowRight className="h-4 w-4" />
					</Button>
				}
			/>
		</>
	);
}

function GasPayerBanner({ address }: { address: string }) {
	return (
		<div className="surface mb-6 px-5 py-3 flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
			<div className="flex items-center gap-2 smallcaps text-text-3">
				<Wallet className="h-3 w-3" />
				Gas payer
			</div>
			<Mono className="text-[12px] flex-1 truncate">{address}</Mono>
			<span className="smallcaps text-text-4 hidden sm:inline">
				pays for setup · doesn&apos;t have to be a member
			</span>
		</div>
	);
}

function NoGasPayerBanner({ reconnecting }: { reconnecting: boolean }) {
	if (reconnecting) {
		return (
			<div className="surface mb-6 px-5 py-3 flex items-center gap-3 border border-border">
				<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<Loader2 className="h-3 w-3 animate-spin" />
					Reconnecting wallet…
				</span>
			</div>
		);
	}
	return (
		<div className="surface mb-6 px-5 py-3 flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 border border-clay/30">
			<div className="flex items-center gap-2 smallcaps text-clay">
				<AlertCircle className="h-3 w-3" />
				Gas payer required
			</div>
			<span className="smallcaps text-text-3 flex-1">
				Connect a wallet to pay setup gas — separate from members.
			</span>
			<WalletConnect />
		</div>
	);
}

type AddResult = { ok: true } | { ok: false; reason: string };
type AddTab = 'passkey' | 'wallet';

function AddMemberPanel({ onAdd }: { onAdd: (m: StoredMember) => AddResult }) {
	const [tab, setTab] = React.useState<AddTab>('passkey');
	const [error, setError] = React.useState<string | null>(null);
	const [info, setInfo] = React.useState<string | null>(null);

	React.useEffect(() => {
		setError(null);
		setInfo(null);
	}, []);

	function dispatch(r: AddResult) {
		if (!r.ok) setError(r.reason);
		else {
			setError(null);
			setInfo('Added.');
			setTimeout(() => setInfo(null), 1600);
		}
		return r;
	}

	return (
		<div className="mt-6 surface p-1">
			<div className="flex items-center gap-1 p-1">
				<TabButton active={tab === 'passkey'} onClick={() => setTab('passkey')}>
					<Fingerprint className="h-3 w-3" />
					Passkey
				</TabButton>
				<TabButton active={tab === 'wallet'} onClick={() => setTab('wallet')}>
					<Wallet className="h-3 w-3" />
					Wallet
				</TabButton>
			</div>
			<div className="px-3 pb-3 pt-1">
				{tab === 'passkey' && (
					<AddPasskeyTab onAdd={(m) => dispatch(onAdd(m))} setError={setError} />
				)}
				{tab === 'wallet' && <AddWalletTab onAdd={(m) => dispatch(onAdd(m))} setError={setError} />}
				{error && (
					<div className="mt-3 flex items-start gap-2 text-[12.5px] text-clay leading-[1.55]">
						<AlertCircle className="h-3.5 w-3.5 mt-[2px] flex-none" />
						{error}
					</div>
				)}
				{info && (
					<div className="mt-3 inline-flex items-center gap-1.5 smallcaps text-sage">
						<Check className="h-3 w-3" />
						{info}
					</div>
				)}
			</div>
		</div>
	);
}

function TabButton({
	active,
	onClick,
	children,
}: {
	active: boolean;
	onClick: () => void;
	children: React.ReactNode;
}) {
	return (
		<button
			type="button"
			onClick={onClick}
			className={`smallcaps inline-flex items-center gap-1.5 px-3 h-7 rounded-md transition-colors ${
				active
					? 'bg-surface-3 text-text border border-border'
					: 'text-text-3 hover:text-text border border-transparent'
			}`}
		>
			{children}
		</button>
	);
}

function AddPasskeyTab({
	onAdd,
	setError,
}: {
	onAdd: (m: StoredMember) => AddResult;
	setError: (e: string | null) => void;
}) {
	const [busy, setBusy] = React.useState(false);

	async function handleEnroll() {
		setBusy(true);
		setError(null);
		try {
			const member = await capturePasskeyMember();
			onAdd(member);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			if (
				msg.toLowerCase().includes('cancel') ||
				msg.toLowerCase().includes('aborted') ||
				msg.toLowerCase().includes('not allowed')
			) {
				setError(null);
			} else {
				setError(msg);
			}
		} finally {
			setBusy(false);
		}
	}

	return (
		<div>
			<p className="text-[12.5px] text-text-3 leading-[1.55]">
				Enroll another passkey. The browser will offer to use this device, a phone or tablet (via QR
				code), or a hardware security key. We authenticate twice: once to register the credential,
				once to extract the PRF seed that drives the encryption identity.
			</p>
			<Button
				variant="secondary"
				size="default"
				onClick={handleEnroll}
				disabled={busy}
				className="mt-3"
			>
				{busy ? (
					<>
						<Loader2 className="h-3.5 w-3.5 animate-spin" /> Waiting for authenticator…
					</>
				) : (
					<>
						<Plus className="h-3.5 w-3.5" /> Add another passkey
					</>
				)}
			</Button>
		</div>
	);
}

function AddWalletTab({
	onAdd,
	setError,
}: {
	onAdd: (m: StoredMember) => AddResult;
	setError: (e: string | null) => void;
}) {
	const wallets = useWallets();
	const [busy, setBusy] = React.useState(false);
	const [pickerOpen, setPickerOpen] = React.useState(false);

	// Filter to wallets that can sign personal messages — this is the only
	// feature we need from the wallet to derive a deterministic encryption seed.
	const compatible = React.useMemo(
		() => wallets.filter((w) => w.features.includes('sui:signPersonalMessage')),
		[wallets],
	);

	async function handlePick(wallet: UiWallet) {
		setBusy(true);
		setError(null);
		try {
			// For Enoki wallets, force a fresh OAuth so the user can pick a
			// different identity than the one used as the importer / a previously-
			// added member. Without this, connect() short-circuits to the cached
			// account and we end up with "already in the roster".
			if (isEnokiWallet(wallet) && wallet.accounts.length > 0) {
				await dAppKit.disconnectWallet();
			}
			// Make sure the wallet has at least one account exposed. If the user has
			// never connected this wallet, the connect handshake also prompts.
			let accounts = wallet.accounts;
			if (accounts.length === 0) {
				// dApp Kit 2 drives the wallet-standard features itself; reaching into
				// `wallet.features` is no longer possible, since a UiWallet only names
				// them.
				const res = await dAppKit.connectWallet({ wallet });
				accounts = res.accounts;
			}
			const account: UiWalletAccount | undefined = accounts[0];
			if (!account) {
				throw new Error(`${wallet.name} did not return any accounts.`);
			}
			const member = await captureWalletMember(wallet, account);
			onAdd(member);
			setPickerOpen(false);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			if (msg.toLowerCase().includes('reject') || msg.toLowerCase().includes('cancel')) {
				setError(null);
			} else {
				setError(msg);
			}
		} finally {
			setBusy(false);
		}
	}

	return (
		<div>
			<p className="text-[12.5px] text-text-3 leading-[1.55]">
				Add any Sui wallet as a member. The wallet signs a fixed personal message; we hash that
				signature into a deterministic seed that derives the wallet&apos;s encryption identity. The
				same wallet will always derive the same identity. Member wallets don&apos;t need any SUI to
				sign for the threshold — gas is paid by the connected gas-payer above.
			</p>
			<p className="mt-2 text-[12px] text-text-4 leading-[1.55]">
				Sign-in-with-Google (zkLogin) wallets don&apos;t produce a stable signature, so they&apos;re
				added as <span className="text-text-3">approver-only</span>: they can vote but cannot
				execute a recovery.
			</p>
			{!pickerOpen ? (
				<Button
					variant="secondary"
					size="default"
					onClick={() => setPickerOpen(true)}
					disabled={busy}
					className="mt-3"
				>
					<Plus className="h-3.5 w-3.5" /> Add wallet member
				</Button>
			) : (
				<div className="mt-3 surface p-2 space-y-1">
					{compatible.length === 0 ? (
						<p className="px-3 py-4 text-[12.5px] text-text-3">
							No Sui wallets detected. Install Slush, Sui Wallet, Phantom, or another Sui-compatible
							wallet, then refresh this page.
						</p>
					) : (
						compatible.map((w) => (
							<button
								key={w.name}
								type="button"
								onClick={() => handlePick(w)}
								disabled={busy}
								className="w-full text-left flex items-center gap-3 px-3 py-2 rounded-md hover:bg-surface-3 transition-colors disabled:opacity-50"
							>
								{w.icon && <img src={w.icon} alt="" className="h-5 w-5 rounded-sm flex-none" />}
								<span className="text-[13px] text-text">{w.name}</span>
								<span className="ml-auto smallcaps text-text-4">
									{isEnokiWallet(w)
										? 'connect'
										: w.accounts[0]
											? `${w.accounts[0].address.slice(0, 6)}…${w.accounts[0].address.slice(-4)}`
											: 'connect'}
								</span>
							</button>
						))
					)}
					<button
						type="button"
						onClick={() => setPickerOpen(false)}
						disabled={busy}
						className="mt-1 w-full text-center smallcaps text-text-4 hover:text-text py-2"
					>
						Cancel
					</button>
					{busy && (
						<div className="px-3 py-2 inline-flex items-center gap-2 smallcaps text-text-3">
							<Loader2 className="h-3 w-3 animate-spin" />
							Waiting for wallet…
						</div>
					)}
				</div>
			)}
		</div>
	);
}

function MemberRow({
	idx,
	isImporter,
	member,
	onRemove,
}: {
	idx: number;
	isImporter: boolean;
	member: StoredMember;
	onRemove: () => void;
}) {
	const display =
		member.kind === 'passkey'
			? `${member.publicKeyHex.slice(0, 10)}…${member.publicKeyHex.slice(-6)}`
			: `${member.address.slice(0, 10)}…${member.address.slice(-6)}`;
	const kindLabel =
		member.kind === 'passkey'
			? 'Passkey'
			: member.kind === 'approver'
				? member.walletName
					? `Approver-only · ${member.walletName}`
					: 'Approver-only'
				: member.walletName
					? `Wallet · ${member.walletName}`
					: 'Wallet';
	const Icon = member.kind === 'passkey' ? Fingerprint : Wallet;
	return (
		<li className="flex items-center gap-3 surface px-4 py-3">
			<span className="font-mono text-[10px] text-text-4 tabular flex-none w-6">
				{String(idx + 1).padStart(2, '0')}
			</span>
			<span
				className={`h-7 w-7 rounded-md flex-none flex items-center justify-center border ${
					isImporter
						? 'bg-clay/15 border-clay/40 text-clay'
						: 'bg-surface-2 border-border text-text-3'
				}`}
			>
				<Icon className="h-3.5 w-3.5" />
			</span>
			<div className="flex flex-col min-w-0 flex-1">
				<div className="flex items-center gap-2 flex-wrap">
					<span className="text-[14px] text-text">
						{isImporter ? 'Initial user' : `Member ${idx + 1}`}
					</span>
					<span className="smallcaps text-text-3">{kindLabel}</span>
				</div>
				<Mono className="text-[12px] text-text-2">{display}</Mono>
			</div>
			{!isImporter && (
				<Button
					variant="ghost"
					size="icon"
					onClick={onRemove}
					className="ml-auto"
					aria-label={`Remove member ${idx + 1}`}
				>
					<Trash2 className="h-3.5 w-3.5" />
				</Button>
			)}
		</li>
	);
}
