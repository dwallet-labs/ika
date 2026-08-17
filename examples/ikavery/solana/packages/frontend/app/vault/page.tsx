'use client';

import { useDynamicContext } from '@dynamic-labs/sdk-react-core';
import { Button, Card, truncateAddress } from '@fesal-packages/ikavery-frontend-ui';
import {
	listAllRecoveries,
	packMemberSlot,
	packSolanaMember,
	SCHEME_WEBAUTHN,
	type DecodedRecovery,
} from '@fesal-packages/ikavery-solana-sdk';
import { Connection, PublicKey } from '@solana/web3.js';
import { useQuery } from '@tanstack/react-query';
import {
	ArrowRight,
	Database,
	Fingerprint,
	HardDrive,
	Hash,
	Loader2,
	Search,
	Wallet,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import { WalletConnect } from '@/components/wallet-connect';
import { rpId, SOLANA_RPC } from '@/lib/env';
import { discoverViaPasskey } from '@/lib/passkey-discover';
import {
	hexToBytes,
	loadActiveImporter,
	loadSavedVaults,
	saveActiveImporter,
	type CachedImporter,
	type SavedVault,
} from '@/lib/storage';

export default function VaultLanding() {
	const router = useRouter();
	const { primaryWallet, sdkHasLoaded } = useDynamicContext();
	const connection = React.useMemo(() => new Connection(SOLANA_RPC, 'confirmed'), []);

	const [savedVaults, setSavedVaults] = React.useState<SavedVault[] | null>(null);
	const [importer, setImporter] = React.useState<CachedImporter | null>(null);
	React.useEffect(() => {
		void loadSavedVaults().then(setSavedVaults);
		void loadActiveImporter().then(setImporter);
	}, []);

	const passkeySlot = React.useMemo(() => {
		if (importer?.kind !== 'passkey') return null;
		return packMemberSlot(SCHEME_WEBAUTHN, hexToBytes(importer.publicKeyHex));
	}, [importer]);

	const walletSlot = React.useMemo(() => {
		if (!primaryWallet?.address) return null;
		try {
			return packSolanaMember(new PublicKey(primaryWallet.address));
		} catch {
			return null;
		}
	}, [primaryWallet?.address]);

	// One `getProgramAccounts` for the whole page — public RPCs throttle that
	// call hard, so we fetch every Recovery once and derive both the passkey
	// and wallet matches client-side. React Query caches the list across
	// tab returns so flipping passkey/wallet doesn't refetch.
	const allRecoveries = useQuery({
		queryKey: ['ikavery-solana.discovery.recoveries'],
		enabled: !!passkeySlot || !!walletSlot,
		queryFn: () => listAllRecoveries(connection),
		staleTime: 30_000,
	});

	const onChainPasskey = React.useMemo(
		() => ({
			isLoading: allRecoveries.isLoading,
			error: allRecoveries.error,
			data:
				passkeySlot && allRecoveries.data
					? matchedRecoveries(allRecoveries.data, passkeySlot)
					: undefined,
		}),
		[allRecoveries.isLoading, allRecoveries.error, allRecoveries.data, passkeySlot],
	);

	const onChainWallet = React.useMemo(
		() => ({
			isLoading: allRecoveries.isLoading,
			error: allRecoveries.error,
			data:
				walletSlot && allRecoveries.data
					? matchedRecoveries(allRecoveries.data, walletSlot)
					: undefined,
		}),
		[allRecoveries.isLoading, allRecoveries.error, allRecoveries.data, walletSlot],
	);

	// Hide on-chain entries already in the local cache so the same id doesn't
	// appear twice — local row carries richer metadata (threshold/members/date).
	const localIds = React.useMemo(
		() => new Set((savedVaults ?? []).map((v) => v.recovery)),
		[savedVaults],
	);
	const passkeyOnly = React.useMemo<DecodedRecovery[]>(() => {
		if (!onChainPasskey.data) return [];
		return onChainPasskey.data.filter((r) => !localIds.has(r.recovery.toBase58()));
	}, [onChainPasskey.data, localIds]);
	const walletOnly = React.useMemo<DecodedRecovery[]>(() => {
		if (!onChainWallet.data) return [];
		const seen = new Set([...localIds, ...passkeyOnly.map((r) => r.recovery.toBase58())]);
		return onChainWallet.data.filter((r) => !seen.has(r.recovery.toBase58()));
	}, [onChainWallet.data, localIds, passkeyOnly]);

	const totalFound = (savedVaults?.length ?? 0) + passkeyOnly.length + walletOnly.length;

	return (
		<>
			<header className="mb-12">
				<span className="smallcaps text-clay">Vault directory</span>
				<h1 className="mt-3 font-display text-[40px] sm:text-[56px] lg:text-[72px] leading-[0.98] tracking-[-0.025em] text-text">
					Open a vault.
					<br />
					<span className="italic text-text-2">Yours, or one you know.</span>
				</h1>
				<p className="mt-5 max-w-[640px] text-[15px] sm:text-[16px] leading-[1.6] text-text-2">
					Vaults sealed in this browser are kept locally. Vaults whose roster includes your passkey
					or connected wallet are discovered on-chain by scanning the ikavery program. Otherwise,
					paste the Recovery PDA you have on hand.
				</p>
			</header>

			<ManualOpen />

			<Section
				title="Saved on this device"
				subtitle="Vaults you sealed in this browser."
				icon={<HardDrive className="h-3.5 w-3.5" />}
			>
				{savedVaults === null ? (
					<SkeletonRows lines={2} />
				) : savedVaults.length === 0 ? (
					<Empty text="No vaults saved here yet. After /setup the vault appears in this list." />
				) : (
					<ul className="divide-y divide-border">
						{savedVaults.map((v) => (
							<SavedRow
								key={v.recovery}
								vault={v}
								onOpen={() => router.push(`/vault/${v.recovery}`)}
							/>
						))}
					</ul>
				)}
			</Section>

			<Section
				title="Found via your passkey"
				subtitle="Find vaults this device's passkey is enrolled in — no wallet needed. Works even if the local cache is gone."
				icon={<Fingerprint className="h-3.5 w-3.5" />}
			>
				<PasskeyDiscover
					connection={connection}
					recoveries={allRecoveries.data}
					importer={importer}
					discovered={passkeyOnly}
					isLoading={onChainPasskey.isLoading}
					error={onChainPasskey.error}
					onPicked={(updated: CachedImporter) => setImporter(updated)}
					onOpenVault={(id) => router.push(`/vault/${id}`)}
				/>
			</Section>

			<Section
				title="Found via your connected wallet"
				subtitle={
					primaryWallet?.address
						? `Recoveries that include ${truncateAddress(primaryWallet.address)} as a member.`
						: !sdkHasLoaded
							? 'Reconnecting wallet…'
							: 'Connect a wallet to scan the program for vaults you belong to.'
				}
				icon={<Wallet className="h-3.5 w-3.5" />}
			>
				{!sdkHasLoaded ? (
					<LoadingRow text="Reconnecting wallet…" />
				) : !walletSlot ? (
					<div className="flex flex-col sm:flex-row sm:items-center gap-3 px-4 py-4">
						<span className="text-[13px] text-text-3 leading-[1.5] flex-1">
							Connect a wallet to scan the program for vaults you belong to.
						</span>
						<WalletConnect />
					</div>
				) : onChainWallet.isLoading ? (
					<LoadingRow text="Scanning the program for matches…" />
				) : onChainWallet.error ? (
					<Empty
						text={`Registry scan failed: ${
							onChainWallet.error instanceof Error
								? onChainWallet.error.message
								: String(onChainWallet.error)
						}`}
					/>
				) : walletOnly.length === 0 ? (
					<Empty
						text={
							(onChainWallet.data?.length ?? 0) > 0
								? 'All wallet matches are already shown above.'
								: 'No vaults on-chain include this wallet.'
						}
					/>
				) : (
					<ul className="divide-y divide-border">
						{walletOnly.map((r) => (
							<ChainRow
								key={r.recovery.toBase58()}
								recovery={r}
								onOpen={() => router.push(`/vault/${r.recovery.toBase58()}`)}
							/>
						))}
					</ul>
				)}
			</Section>

			{totalFound === 0 &&
				savedVaults !== null &&
				!onChainPasskey.isLoading &&
				!onChainWallet.isLoading && (
					<Card tone="raised" className="mt-10 px-5 sm:px-8 py-6 sm:py-7">
						<div className="flex items-start gap-4">
							<div className="h-9 w-9 flex-none rounded border border-border flex items-center justify-center">
								<Database className="h-3.5 w-3.5 text-text-3" />
							</div>
							<div className="flex-1">
								<h3 className="font-display text-[22px] sm:text-[26px] leading-[1.1] text-text">
									No vaults yet.
								</h3>
								<p className="mt-2 text-[14px] text-text-2 leading-[1.55] max-w-[520px]">
									{primaryWallet
										? 'Place a Solana key behind a quorum-gated dWallet to seal your first one.'
										: 'Set up your first vault now, or connect a wallet to discover vaults you already belong to.'}
								</p>
								<div className="mt-4 flex flex-wrap items-center gap-3">
									<Button
										variant="primary"
										size="default"
										onClick={() => router.push('/setup/connect')}
									>
										Set up a new vault
										<ArrowRight className="h-4 w-4" />
									</Button>
									{!primaryWallet && <WalletConnect />}
								</div>
							</div>
						</div>
					</Card>
				)}
		</>
	);
}

function ManualOpen() {
	const router = useRouter();
	const [value, setValue] = React.useState('');
	const valid = isValidPubkey(value.trim());

	return (
		<Card tone="raised" className="mb-10 px-5 sm:px-8 py-5 sm:py-6">
			<div className="flex items-start gap-4">
				<div className="h-9 w-9 flex-none rounded border border-border flex items-center justify-center">
					<Hash className="h-3.5 w-3.5 text-clay" />
				</div>
				<div className="flex-1 min-w-0">
					<div className="smallcaps text-text-3">Open by recovery PDA</div>
					<form
						className="mt-3 flex flex-col sm:flex-row gap-3"
						onSubmit={(e) => {
							e.preventDefault();
							if (valid) router.push(`/vault/${value.trim()}`);
						}}
					>
						<input
							value={value}
							onChange={(e) => setValue(e.target.value)}
							placeholder="9wXJp1xs… (base58)"
							spellCheck={false}
							autoCorrect="off"
							autoCapitalize="off"
							className="flex-1 min-w-0 px-3 h-10 bg-surface border border-border rounded-md font-mono text-[13px] tabular text-text placeholder:text-text-4 focus:outline-none focus:border-clay focus:ring-1 focus:ring-clay/30"
						/>
						<Button type="submit" variant="primary" size="default" disabled={!valid}>
							<Search className="h-3.5 w-3.5" />
							Open
						</Button>
					</form>
				</div>
			</div>
		</Card>
	);
}

function Section({
	title,
	subtitle,
	icon,
	children,
}: {
	title: string;
	subtitle: string;
	icon: React.ReactNode;
	children: React.ReactNode;
}) {
	return (
		<section className="mt-8">
			<header className="mb-3 flex items-baseline justify-between">
				<div>
					<div className="smallcaps text-text-3 inline-flex items-center gap-1.5">
						<span className="text-clay">{icon}</span>
						{title}
					</div>
					<p className="mt-1 text-[12.5px] text-text-3 leading-[1.5]">{subtitle}</p>
				</div>
			</header>
			<Card tone="raised" className="overflow-hidden p-0">
				<div className="px-2 py-1">{children}</div>
			</Card>
		</section>
	);
}

function SavedRow({ vault, onOpen }: { vault: SavedVault; onOpen: () => void }) {
	return (
		<li>
			<button
				type="button"
				onClick={onOpen}
				className="w-full text-left flex items-center gap-4 px-4 py-4 hover:bg-surface-3/50 transition-colors group"
			>
				<div className="flex-1 min-w-0">
					<div className="font-mono text-[13px] tabular text-text truncate">{vault.recovery}</div>
					<div className="mt-1 flex items-center gap-3 smallcaps text-text-3">
						<span>
							{vault.threshold} of {vault.totalMembers}
						</span>
						<span className="text-text-4">·</span>
						<span>dWallet {truncateAddress(vault.dwalletPubkey)}</span>
						<span className="text-text-4">·</span>
						<span>{relativeTime(vault.createdAt)}</span>
					</div>
				</div>
				<ArrowRight className="h-3.5 w-3.5 text-text-3 group-hover:text-clay transition-colors" />
			</button>
		</li>
	);
}

function ChainRow({ recovery, onOpen }: { recovery: DecodedRecovery; onOpen: () => void }) {
	const id = recovery.recovery.toBase58();
	return (
		<li>
			<button
				type="button"
				onClick={onOpen}
				className="w-full text-left flex items-center gap-4 px-4 py-4 hover:bg-surface-3/50 transition-colors group"
			>
				<div className="flex-1 min-w-0">
					<div className="font-mono text-[13px] tabular text-text truncate">{id}</div>
					<div className="mt-1 flex items-center gap-3 smallcaps text-text-3">
						<span>
							{recovery.account.threshold} of {recovery.account.members.length}
						</span>
						<span className="text-text-4">·</span>
						<span>dWallet {truncateAddress(recovery.account.dwallet.toBase58())}</span>
					</div>
				</div>
				<ArrowRight className="h-3.5 w-3.5 text-text-3 group-hover:text-clay transition-colors" />
			</button>
		</li>
	);
}

function matchedRecoveries(recoveries: DecodedRecovery[], slot: Uint8Array): DecodedRecovery[] {
	const out: DecodedRecovery[] = [];
	for (const r of recoveries) {
		for (const m of r.account.members) {
			if (slotEq(m, slot)) {
				out.push(r);
				break;
			}
		}
	}
	return out;
}

function slotEq(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

function PasskeyDiscover({
	connection,
	recoveries,
	importer,
	discovered,
	isLoading,
	error,
	onPicked,
	onOpenVault,
}: {
	connection: Connection;
	recoveries: DecodedRecovery[] | undefined;
	importer: CachedImporter | null;
	discovered: DecodedRecovery[];
	isLoading: boolean;
	error: unknown;
	onPicked: (updated: CachedImporter) => void;
	onOpenVault: (recoveryId: string) => void;
}) {
	const [running, setRunning] = React.useState(false);
	const [discoverErr, setDiscoverErr] = React.useState<string | null>(null);
	const [foundIds, setFoundIds] = React.useState<string[] | null>(null);

	async function handleDiscover() {
		setRunning(true);
		setDiscoverErr(null);
		setFoundIds(null);
		try {
			const res = await discoverViaPasskey(connection, rpId, recoveries);
			const cached: CachedImporter = {
				kind: 'passkey',
				credentialIdHex: res.credentialIdHex,
				publicKeyHex: res.publicKeyHex,
				createdAt: Date.now(),
			};
			await saveActiveImporter(cached);
			onPicked(cached);
			setFoundIds(res.recoveryIds);
		} catch (e) {
			setDiscoverErr(e instanceof Error ? e.message : String(e));
		} finally {
			setRunning(false);
		}
	}

	if (importer?.kind === 'passkey') {
		return (
			<div>
				<div className="px-4 py-3 flex flex-wrap items-center justify-between gap-3">
					<div className="text-[12.5px] text-text-3 leading-[1.5]">
						Cached passkey:{' '}
						<span className="font-mono text-text-2">
							{truncateAddress(importer.publicKeyHex, 8, 6)}
						</span>
					</div>
					<Button variant="ghost" size="default" onClick={handleDiscover} disabled={running}>
						{running ? (
							<>
								<Loader2 className="h-3.5 w-3.5 animate-spin" />
								Looking up…
							</>
						) : (
							<>
								<Fingerprint className="h-3.5 w-3.5" />
								Use a different passkey
							</>
						)}
					</Button>
				</div>
				{isLoading ? (
					<LoadingRow text="Scanning the program for matches…" />
				) : error ? (
					<Empty
						text={`Registry scan failed: ${error instanceof Error ? error.message : String(error)}`}
					/>
				) : discovered.length === 0 ? (
					<Empty text="No vaults on-chain include this passkey." />
				) : (
					<ul className="divide-y divide-border">
						{discovered.map((r) => (
							<ChainRow
								key={r.recovery.toBase58()}
								recovery={r}
								onOpen={() => onOpenVault(r.recovery.toBase58())}
							/>
						))}
					</ul>
				)}
				{discoverErr && (
					<div className="px-4 py-3 text-[12.5px] text-clay leading-[1.5]">{discoverErr}</div>
				)}
			</div>
		);
	}

	return (
		<div>
			<div className="px-4 py-5">
				<p className="text-[13px] text-text-2 leading-[1.55] mb-3">
					Pick a passkey you used to seal a vault on this site. We&apos;ll recover its public key
					from the assertion signature, look it up in the on-chain registry, and re-cache the
					identity locally.
				</p>
				<Button variant="primary" size="default" onClick={handleDiscover} disabled={running}>
					{running ? (
						<>
							<Loader2 className="h-3.5 w-3.5 animate-spin" />
							Looking up…
						</>
					) : (
						<>
							<Fingerprint className="h-3.5 w-3.5" />
							Find vaults via passkey
						</>
					)}
				</Button>
				{discoverErr && (
					<div className="mt-3 text-[12.5px] text-clay leading-[1.5]">{discoverErr}</div>
				)}
				{foundIds && foundIds.length === 0 && (
					<div className="mt-3 text-[12.5px] text-text-3 leading-[1.5]">
						No vaults found for that passkey.
					</div>
				)}
			</div>
		</div>
	);
}

function Empty({ text }: { text: string }) {
	return <div className="px-4 py-6 text-[13px] text-text-3 leading-[1.5]">{text}</div>;
}

function LoadingRow({ text }: { text: string }) {
	return (
		<div className="flex items-center gap-2 text-text-3 text-[13px] py-2 px-4">
			<Loader2 className="h-3.5 w-3.5 animate-spin" />
			{text}
		</div>
	);
}

function SkeletonRows({ lines }: { lines: number }) {
	return (
		<div className="px-4 py-4 space-y-3">
			{Array.from({ length: lines }).map((_, i) => (
				<div key={i} className="h-4 w-full max-w-[480px] bg-surface-3 rounded animate-pulse" />
			))}
		</div>
	);
}

function isValidPubkey(s: string): boolean {
	try {
		new PublicKey(s);
		return true;
	} catch {
		return false;
	}
}

function relativeTime(ts: number): string {
	const diff = Date.now() - ts;
	const m = Math.round(diff / 60_000);
	if (m < 1) return 'just now';
	if (m < 60) return `${m}m ago`;
	const h = Math.round(m / 60);
	if (h < 24) return `${h}h ago`;
	const d = Math.round(h / 24);
	return `${d}d ago`;
}
