'use client';

import { useDynamicContext } from '@dynamic-labs/sdk-react-core';
import { registerPasskey } from '@fesal-packages/ikavery-core';
import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import { PublicKey } from '@solana/web3.js';
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
import { rpId, rpName } from '@/lib/env';
import { bytesToHex } from '@/lib/storage';
import {
	memberDisplayId,
	memberKey,
	memberKindLabel,
	sameMember,
	useSetup,
	type StoredMember,
} from '@/store/setup';

import { FieldLabel, Mono, StepFooter, StepHeader } from '../_parts';

const MAX_MEMBERS = 8;

export default function ThresholdStep() {
	const router = useRouter();
	const importer = useSetup((s) => s.importer);
	const members = useSetup((s) => s.members);
	const setMembers = useSetup((s) => s.setMembers);
	const threshold = useSetup((s) => s.threshold);
	const setThreshold = useSetup((s) => s.setThreshold);
	const { primaryWallet, sdkHasLoaded } = useDynamicContext();

	React.useEffect(() => {
		if (!importer) router.replace('/setup/connect');
	}, [importer, router]);

	if (!importer) return null;

	const N = members.length;
	const validThreshold = Math.max(1, Math.min(N, threshold));

	function addMember(m: StoredMember): { ok: true } | { ok: false; reason: string } {
		for (const existing of members) {
			if (sameMember(existing, m)) {
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
		// The importer is locked into the roster — it lives at index 0. They can
		// switch identities from /setup/connect.
		if (sameMember(target, importer)) return;
		const next = members.filter((_, i) => i !== idx);
		setMembers(next);
		if (threshold > next.length) setThreshold(Math.max(1, next.length));
	}

	return (
		<>
			<StepHeader
				ord="02 / Quorum"
				title="Pick a threshold"
				italic="and a roster."
				hint="A threshold is the minimum number of members that must approve a recovery. Each member is either a passkey (this device, a phone, a hardware key) or a Solana wallet — you can mix and match."
			/>

			{sdkHasLoaded ? (
				primaryWallet ? (
					<GasPayerBanner address={primaryWallet.address} />
				) : (
					<NoGasPayerBanner />
				)
			) : (
				<ReconnectingBanner />
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
						onChange={(e) => setThreshold(Number.parseInt(e.target.value, 10))}
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
							{N} member{N === 1 ? '' : 's'} · max {MAX_MEMBERS}
						</span>
					</div>
					<ul className="space-y-2.5">
						{members.map((m, i) => (
							<MemberRow
								key={memberKey(m)}
								idx={i}
								isImporter={sameMember(m, importer)}
								member={m}
								onRemove={() => removeMember(i)}
							/>
						))}
					</ul>

					{members.length < MAX_MEMBERS ? (
						<AddMemberPanel onAdd={addMember} />
					) : (
						<p className="mt-5 inline-flex items-center gap-2 smallcaps text-text-4">
							<AlertCircle className="h-3 w-3" />
							Roster is full · MAX_MEMBERS = {MAX_MEMBERS}
						</p>
					)}
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

function NoGasPayerBanner() {
	return (
		<div className="surface mb-6 px-5 py-3 flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 border border-clay/30">
			<div className="flex items-center gap-2 smallcaps text-clay">
				<AlertCircle className="h-3 w-3" />
				Gas payer required
			</div>
			<span className="smallcaps text-text-3 flex-1">
				Connect a Solana wallet to pay setup gas — separate from members.
			</span>
			<WalletConnect />
		</div>
	);
}

function ReconnectingBanner() {
	return (
		<div className="surface mb-6 px-5 py-3 flex items-center gap-3 border border-border">
			<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
				<Loader2 className="h-3 w-3 animate-spin" />
				Reconnecting wallet…
			</span>
		</div>
	);
}

type AddResult = { ok: true } | { ok: false; reason: string };
type AddTab = 'passkey' | 'wallet';

function AddMemberPanel({ onAdd }: { onAdd: (m: StoredMember) => AddResult }) {
	const [tab, setTab] = React.useState<AddTab>('passkey');
	const [error, setError] = React.useState<string | null>(null);
	const [info, setInfo] = React.useState<string | null>(null);

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
			const userId = crypto.getRandomValues(new Uint8Array(16));
			const cred = await registerPasskey({
				rpId,
				rpName,
				userId,
				userName: 'ikavery-solana-member',
				userDisplayName: 'Ikavery (member)',
			});
			const member: StoredMember = {
				kind: 'passkey',
				credentialIdHex: bytesToHex(cred.credentialId),
				publicKeyHex: bytesToHex(cred.publicKey),
			};
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
				code), or a hardware security key. The on-chain member id is the 33-byte compressed P-256
				public key — Solana&apos;s native secp256r1 precompile verifies the assertion.
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
	const [value, setValue] = React.useState('');

	function handleAdd() {
		const trimmed = value.trim();
		if (!trimmed) return;
		let pubkey: PublicKey;
		try {
			pubkey = new PublicKey(trimmed);
		} catch {
			setError('Not a valid base58 Solana address.');
			return;
		}
		const result = onAdd({ kind: 'wallet', address: pubkey.toBase58() });
		if (!result.ok) return;
		setValue('');
		setError(null);
	}

	return (
		<div>
			<p className="text-[12.5px] text-text-3 leading-[1.55]">
				Add any Solana wallet as a member by pasting their base58 pubkey. They sign the on-chain{' '}
				<Mono>approve</Mono> ix when a recovery is in flight — they don&apos;t need any SOL for
				setup; the gas payer above covers it.
			</p>
			<div className="mt-3 flex flex-col sm:flex-row gap-2">
				<input
					type="text"
					value={value}
					onChange={(e) => {
						setValue(e.target.value);
						setError(null);
					}}
					onKeyDown={(e) => {
						if (e.key === 'Enter') {
							e.preventDefault();
							handleAdd();
						}
					}}
					placeholder="9wXJp1xs…"
					spellCheck={false}
					autoCorrect="off"
					autoCapitalize="off"
					className="flex-1 font-mono text-[13px] tabular text-text bg-surface border border-border rounded-md px-3 h-10 focus:outline-none focus:border-clay/60 placeholder:text-text-4"
				/>
				<Button variant="secondary" size="default" onClick={handleAdd}>
					<Plus className="h-3.5 w-3.5" /> Add wallet
				</Button>
			</div>
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
	const Icon = member.kind === 'passkey' ? Fingerprint : Wallet;
	const kindLabel = isImporter
		? memberKindLabel(member)
		: member.kind === 'passkey'
			? 'Passkey'
			: 'Wallet';
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
				<Mono className="text-[12px] text-text-2">{memberDisplayId(member)}</Mono>
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
