'use client';

import { Button, Card } from '@fesal-packages/ikavery-frontend-ui';
import { useCurrentAccount, useWalletConnection } from '@mysten/dapp-kit-react';
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
import { deriveIdentity } from '@/lib/derive';
import { env } from '@/lib/env';
import { discoverViaPasskey } from '@/lib/passkey-discover';
import { useRecoveryClient } from '@/lib/recovery-client-context';
import { listRecoveriesForMember, memberIdFor } from '@/lib/registry';
import {
	bytesToHex,
	hexToBytes,
	loadActiveImporter,
	loadSavedVaults,
	saveActiveImporter,
	type CachedImporter,
	type SavedVault,
} from '@/lib/storage';

export default function VaultLanding() {
	const router = useRouter();
	const account = useCurrentAccount();
	const { isConnecting: walletReconnecting } = useWalletConnection();
	const { suiClient } = useRecoveryClient();

	const [savedVaults, setSavedVaults] = React.useState<SavedVault[] | null>(null);
	const [importer, setImporter] = React.useState<CachedImporter | null>(null);
	React.useEffect(() => {
		void loadSavedVaults().then(setSavedVaults);
		void loadActiveImporter().then(setImporter);
	}, []);

	const passkeyMemberId = React.useMemo(() => {
		if (importer?.kind !== 'passkey') return null;
		return memberIdFor('webauthn', hexToBytes(importer.publicKeyHex));
	}, [importer]);

	// Wallet lookup uses the connected account's pubkey (32B = ed25519, 33B is
	// ambiguous between secp256k1 and r1 — try both and union the results, since
	// each candidate is a single read-only simulateTransaction).
	const walletPublicKey = React.useMemo(() => {
		if (!account) return null;
		return new Uint8Array(account.publicKey);
	}, [account]);

	const onChain = useQuery({
		queryKey: ['registry.wallet', account?.address ?? '_', suiClient ? 'ready' : '_'],
		enabled: !!account && !!walletPublicKey && !!suiClient,
		queryFn: async () => {
			if (!suiClient || !walletPublicKey) return [] as string[];
			const ids = new Set<string>();
			if (walletPublicKey.length === 32) {
				for (const id of await listRecoveriesForMember(
					suiClient,
					memberIdFor('ed25519', walletPublicKey),
				)) {
					ids.add(id);
				}
			} else if (walletPublicKey.length === 33) {
				for (const scheme of ['secp256k1', 'secp256r1'] as const) {
					for (const id of await listRecoveriesForMember(
						suiClient,
						memberIdFor(scheme, walletPublicKey),
					)) {
						ids.add(id);
					}
				}
			}
			return Array.from(ids);
		},
		staleTime: 30_000,
	});

	const onChainPasskey = useQuery({
		queryKey: [
			'registry.passkey',
			importer?.kind === 'passkey' ? importer.publicKeyHex : '_',
			suiClient ? 'ready' : '_',
		],
		enabled: !!passkeyMemberId && !!suiClient,
		queryFn: async () => {
			if (!suiClient || !passkeyMemberId) return [] as string[];
			return listRecoveriesForMember(suiClient, passkeyMemberId);
		},
		staleTime: 30_000,
	});

	// Hide on-chain entries already in the local cache so the same id doesn't
	// appear twice — local row carries richer metadata (threshold/members/date).
	const onChainOnly = React.useMemo(() => {
		if (!onChain.data) return [];
		const localIds = new Set((savedVaults ?? []).map((v) => v.recoveryId));
		return onChain.data.filter((id) => !localIds.has(id));
	}, [onChain.data, savedVaults]);

	const onChainPasskeyOnly = React.useMemo(() => {
		if (!onChainPasskey.data) return [];
		const seen = new Set([...(savedVaults ?? []).map((v) => v.recoveryId), ...onChainOnly]);
		return onChainPasskey.data.filter((id) => !seen.has(id));
	}, [onChainPasskey.data, savedVaults, onChainOnly]);

	const totalFound = (savedVaults?.length ?? 0) + onChainOnly.length + onChainPasskeyOnly.length;

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
					Vaults sealed on this device are kept locally. Vaults that include your connected wallet
					are discovered on-chain through the recovery registry. Otherwise, paste a recovery id you
					have on hand.
				</p>
			</header>

			{/* Manual lookup — always visible, sets the tone that the id is the */}
			{/* primary handle */}
			<ManualOpen />

			{/* Local cache */}
			<Section
				title="Saved on this device"
				subtitle="Vaults you sealed in this browser."
				icon={<HardDrive className="h-3.5 w-3.5" />}
			>
				{savedVaults === null ? (
					<Skeleton lines={2} />
				) : savedVaults.length === 0 ? (
					<Empty text="No vaults saved here yet. After /setup the vault appears in this list." />
				) : (
					<ul className="divide-y divide-border">
						{savedVaults.map((v) => (
							<SavedRow
								key={v.recoveryId}
								vault={v}
								onOpen={() => router.push(`/vault/${v.recoveryId}`)}
							/>
						))}
					</ul>
				)}
			</Section>

			{/* Passkey-based registry lookup */}
			<Section
				title="Found via your passkey"
				subtitle="Find vaults this device's passkey is enrolled in — no wallet needed. Works even if local cache is gone."
				icon={<Fingerprint className="h-3.5 w-3.5" />}
			>
				<PasskeyDiscover
					importer={importer}
					discovered={onChainPasskeyOnly}
					isLoading={onChainPasskey.isLoading}
					error={onChainPasskey.error}
					onPicked={(updated: CachedImporter) => setImporter(updated)}
					onOpenVault={(id) => router.push(`/vault/${id}`)}
				/>
			</Section>

			{/* On-chain registry lookup */}
			<Section
				title="Found via your connected wallet"
				subtitle={
					account
						? `Recoveries that include ${truncate(account.address)} as a member.`
						: walletReconnecting
							? 'Reconnecting wallet…'
							: 'Connect a wallet to scan the registry for vaults you belong to.'
				}
				icon={<Wallet className="h-3.5 w-3.5" />}
			>
				{!account ? (
					walletReconnecting ? (
						<div className="flex items-center gap-2 text-text-3 text-[13px] py-2 px-4">
							<Loader2 className="h-3.5 w-3.5 animate-spin" />
							Reconnecting wallet…
						</div>
					) : (
						<div className="flex flex-col sm:flex-row sm:items-center gap-3 px-4 py-4">
							<span className="text-[13px] text-text-3 leading-[1.5] flex-1">
								Connect a wallet to scan the registry for vaults you belong to.
							</span>
							<WalletConnect />
						</div>
					)
				) : onChain.isLoading ? (
					<div className="flex items-center gap-2 text-text-3 text-[13px] py-2">
						<Loader2 className="h-3.5 w-3.5 animate-spin" />
						Reading registry…
					</div>
				) : onChain.error ? (
					<Empty text={`Registry lookup failed: ${String(onChain.error)}`} />
				) : onChainOnly.length === 0 ? (
					<Empty
						text={
							(onChain.data?.length ?? 0) > 0
								? 'All on-chain matches are already shown above.'
								: 'No vaults on-chain include this wallet.'
						}
					/>
				) : (
					<ul className="divide-y divide-border">
						{onChainOnly.map((id) => (
							<ChainRow key={id} recoveryId={id} onOpen={() => router.push(`/vault/${id}`)} />
						))}
					</ul>
				)}
			</Section>

			{totalFound === 0 && savedVaults !== null && !onChain.isLoading && (
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
								{account
									? 'Place a Solana key behind a passkey-gated quorum to seal your first one.'
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
								{!account && <WalletConnect />}
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
	const valid = isValidObjectId(value.trim());

	return (
		<Card tone="raised" className="mb-10 px-5 sm:px-8 py-5 sm:py-6">
			<div className="flex items-start gap-4">
				<div className="h-9 w-9 flex-none rounded border border-border flex items-center justify-center">
					<Hash className="h-3.5 w-3.5 text-clay" />
				</div>
				<div className="flex-1 min-w-0">
					<div className="smallcaps text-text-3">Open by recovery id</div>
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
							placeholder="0x…"
							spellCheck={false}
							className="flex-1 min-w-0 px-3 h-10 bg-surface border border-border rounded-[var(--radius-input)] font-mono text-[13px] tabular text-text placeholder:text-text-4 focus:outline-none focus:border-clay focus:ring-1 focus:ring-clay/30"
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
					<div className="font-mono text-[13px] tabular text-text truncate">{vault.recoveryId}</div>
					<div className="mt-1 flex items-center gap-3 smallcaps text-text-3">
						<span>
							{vault.threshold} of {vault.totalMembers}
						</span>
						<span className="text-text-4">·</span>
						<span>{relativeTime(vault.createdAt)}</span>
					</div>
				</div>
				<ArrowRight className="h-3.5 w-3.5 text-text-3 group-hover:text-clay transition-colors" />
			</button>
		</li>
	);
}

function ChainRow({ recoveryId, onOpen }: { recoveryId: string; onOpen: () => void }) {
	return (
		<li>
			<button
				type="button"
				onClick={onOpen}
				className="w-full text-left flex items-center gap-4 px-4 py-4 hover:bg-surface-3/50 transition-colors group"
			>
				<div className="flex-1 min-w-0">
					<div className="font-mono text-[13px] tabular text-text truncate">{recoveryId}</div>
					<div className="mt-1 smallcaps text-text-3">On-chain · membership confirmed</div>
				</div>
				<ArrowRight className="h-3.5 w-3.5 text-text-3 group-hover:text-clay transition-colors" />
			</button>
		</li>
	);
}

function PasskeyDiscover({
	importer,
	discovered,
	isLoading,
	error,
	onPicked,
	onOpenVault,
}: {
	importer: CachedImporter | null;
	discovered: string[];
	isLoading: boolean;
	error: unknown;
	onPicked: (updated: CachedImporter) => void;
	onOpenVault: (recoveryId: string) => void;
}) {
	const { suiClient } = useRecoveryClient();
	const [running, setRunning] = React.useState(false);
	const [discoverErr, setDiscoverErr] = React.useState<string | null>(null);
	const [foundIds, setFoundIds] = React.useState<string[] | null>(null);

	async function handleDiscover() {
		if (!suiClient) return;
		setRunning(true);
		setDiscoverErr(null);
		setFoundIds(null);
		try {
			const res = await discoverViaPasskey(suiClient, env.rpId);
			const identity = await deriveIdentity(res.prfOutput);
			const cached: CachedImporter = {
				kind: 'passkey',
				credentialIdHex: res.credentialIdHex,
				publicKeyHex: res.publicKeyHex,
				encryptionKeysBytesHex: bytesToHex(identity.keysBytes),
				encryptionAddress: identity.encryptionAddress,
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

	// Has cached passkey identity → show registry results from the parent query.
	if (importer?.kind === 'passkey') {
		return (
			<div>
				<div className="px-4 py-3 flex flex-wrap items-center justify-between gap-3">
					<div className="text-[12.5px] text-text-3 leading-[1.5]">
						Cached passkey:{' '}
						<span className="font-mono text-text-2">{truncate(importer.publicKeyHex, 8, 6)}</span>
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
					<div className="flex items-center gap-2 text-text-3 text-[13px] py-2 px-4">
						<Loader2 className="h-3.5 w-3.5 animate-spin" />
						Reading registry…
					</div>
				) : error ? (
					<Empty text={`Registry lookup failed: ${String(error)}`} />
				) : discovered.length === 0 ? (
					<Empty text="No vaults on-chain include this passkey." />
				) : (
					<ul className="divide-y divide-border">
						{discovered.map((id) => (
							<ChainRow key={id} recoveryId={id} onOpen={() => onOpenVault(id)} />
						))}
					</ul>
				)}
				{discoverErr && (
					<div className="px-4 py-3 text-[12.5px] text-clay leading-[1.5]">{discoverErr}</div>
				)}
			</div>
		);
	}

	// No cached passkey → show the discover button.
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

function Skeleton({ lines }: { lines: number }) {
	return (
		<div className="px-4 py-4 space-y-3">
			{Array.from({ length: lines }).map((_, i) => (
				<div key={i} className="h-4 w-full max-w-[480px] bg-surface-3 rounded animate-pulse" />
			))}
		</div>
	);
}

function truncate(addr: string, head = 6, tail = 4): string {
	if (addr.length <= head + tail + 1) return addr;
	return `${addr.slice(0, head)}…${addr.slice(-tail)}`;
}

function isValidObjectId(s: string): boolean {
	return /^0x[0-9a-fA-F]{1,64}$/.test(s);
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
