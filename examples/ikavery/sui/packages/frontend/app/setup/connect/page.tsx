'use client';

import { Button, Card, CardContent } from '@fesal-packages/ikavery-frontend-ui';
import type { UiWallet, UiWalletAccount } from '@mysten/dapp-kit-core';
import { useWallets } from '@mysten/dapp-kit-react';
import { isEnokiWallet } from '@mysten/enoki';
import {
	AlertCircle,
	ArrowRight,
	CheckCircle2,
	Fingerprint,
	Loader2,
	RotateCcw,
	Wallet,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import * as React from 'react';

import { usePasskey } from '@/hooks/use-passkey';
import { dAppKit } from '@/lib/dapp-kit';
import { captureWalletMember } from '@/lib/member-identity';
import {
	clearActiveImporter,
	loadActiveImporter,
	saveActiveImporter,
	type CachedImporter,
} from '@/lib/storage';
import { useSetup, type StoredMember } from '@/store/setup';

import { Mono, StepFooter, StepHeader } from '../_parts';

export default function ConnectStep() {
	const router = useRouter();
	const importer = useSetup((s) => s.importer);
	const setImporter = useSetup((s) => s.setImporter);
	const [hostname, setHostname] = React.useState('');

	React.useEffect(() => {
		setHostname(window.location.hostname);
	}, []);

	// On mount, hydrate the store from any cached importer (passkey or wallet).
	React.useEffect(() => {
		let cancelled = false;
		void (async () => {
			if (importer) return;
			const cached = await loadActiveImporter();
			if (!cancelled && cached) setImporter(cachedToStored(cached));
		})();
		return () => {
			cancelled = true;
		};
	}, [importer, setImporter]);

	async function handleReset() {
		await clearActiveImporter();
		setImporter(null);
		window.location.reload();
	}

	return (
		<>
			<StepHeader
				ord="01 / Initial user"
				title="Pick your identity"
				italic="for this vault."
				hint="The initial user is whoever runs setup. It can be a passkey (Touch ID, Face ID, hardware key) or any Sui wallet that can sign personal messages. The encryption key you derive here decrypts shares produced for you. Gas is paid separately by the wallet you connect from the navbar."
			/>

			<div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
				<PasskeyCard hostname={hostname} importer={importer} onReady={(m) => setImporter(m)} />
				<WalletCard importer={importer} onReady={(m) => setImporter(m)} />
			</div>

			{importer && importer.kind !== 'approver' && <ReadyBanner importer={importer} />}

			<StepFooter
				hint={
					importer
						? 'Identity cached locally. You can switch to a different identity by resetting below.'
						: 'Pick the path that fits — passkeys are great for personal vaults; a wallet works if you already have one you trust for signing.'
				}
				back={
					importer && (
						<Button variant="ghost" size="default" onClick={handleReset}>
							<RotateCcw className="h-3.5 w-3.5" /> Reset initial user
						</Button>
					)
				}
				next={
					<Button
						variant="primary"
						size="lg"
						disabled={!importer}
						onClick={() => router.push('/setup/threshold')}
					>
						Continue
						<ArrowRight className="h-4 w-4" />
					</Button>
				}
			/>
		</>
	);
}

function cachedToStored(c: CachedImporter): StoredMember {
	if (c.kind === 'passkey') {
		return {
			kind: 'passkey',
			credentialIdHex: c.credentialIdHex,
			publicKeyHex: c.publicKeyHex,
			encryptionKeysBytesHex: c.encryptionKeysBytesHex,
			encryptionAddress: c.encryptionAddress,
		};
	}
	return {
		kind: 'wallet',
		address: c.address,
		walletName: c.walletName,
		scheme: c.scheme,
		publicKeyHex: c.publicKeyHex,
		encryptionKeysBytesHex: c.encryptionKeysBytesHex,
		encryptionAddress: c.encryptionAddress,
	};
}

function storedToCached(m: StoredMember): CachedImporter {
	if (m.kind === 'passkey') {
		return {
			kind: 'passkey',
			credentialIdHex: m.credentialIdHex,
			publicKeyHex: m.publicKeyHex,
			encryptionKeysBytesHex: m.encryptionKeysBytesHex,
			encryptionAddress: m.encryptionAddress,
			createdAt: Date.now(),
		};
	}
	if (m.kind === 'approver') {
		// The importer must hold an encryption identity — approver-only members
		// can't take this seat. Caller (`handlePick`) guards against this; we
		// throw here as a defense-in-depth so the impossible case fails loudly.
		throw new Error('storedToCached: approver-only member cannot be the importer');
	}
	return {
		kind: 'wallet',
		address: m.address,
		walletName: m.walletName,
		scheme: m.scheme,
		publicKeyHex: m.publicKeyHex,
		encryptionKeysBytesHex: m.encryptionKeysBytesHex,
		encryptionAddress: m.encryptionAddress,
		createdAt: Date.now(),
	};
}

function PasskeyCard({
	hostname,
	importer,
	onReady,
}: {
	hostname: string;
	importer: StoredMember | null;
	onReady: (m: StoredMember) => void;
}) {
	const { state, enroll } = usePasskey();
	const isActive = importer?.kind === 'passkey';
	const busy = state.stage === 'registering' || state.stage === 'deriving';

	React.useEffect(() => {
		if (state.stage === 'ready' && !isActive) {
			const stored: StoredMember = {
				kind: 'passkey',
				credentialIdHex: state.importer.credentialIdHex,
				publicKeyHex: state.importer.publicKeyHex,
				encryptionKeysBytesHex: state.importer.encryptionKeysBytesHex,
				encryptionAddress: state.importer.encryptionAddress,
			};
			onReady(stored);
		}
	}, [state, isActive, onReady]);

	async function handleEnroll() {
		try {
			await enroll();
		} catch {
			/* state already reflects error */
		}
	}

	return (
		<Card tone="raised" className="p-0 overflow-hidden">
			<div className="px-6 py-4 border-b border-border flex items-baseline justify-between">
				<span className="smallcaps text-text-2 inline-flex items-center gap-1.5">
					<Fingerprint className="h-3 w-3" />
					Passkey
				</span>
				{isActive && (
					<span className="smallcaps text-sage inline-flex items-center gap-1">
						<CheckCircle2 className="h-3 w-3" /> Active
					</span>
				)}
			</div>
			<CardContent className="p-6 sm:p-7 space-y-5">
				<ol className="space-y-3 text-[14px] text-text-2 leading-[1.6]">
					<Step n="i">
						Browser creates a new WebAuthn credential bound to{' '}
						<Mono className="text-[12px]">{hostname || 'this site'}</Mono>.
					</Step>
					<Step n="ii">
						We extract a 32-byte PRF seed. The authenticator never reveals the secret; the browser
						stays sandboxed.
					</Step>
					<Step n="iii">
						The seed deterministically derives an Ika encryption identity. Only this passkey can
						recreate it.
					</Step>
				</ol>

				{state.stage === 'error' && (
					<div className="flex items-start gap-2 text-[13px] text-clay leading-[1.55]">
						<AlertCircle className="h-3.5 w-3.5 mt-[2px] flex-none" />
						{state.message}
					</div>
				)}

				<Button
					size="lg"
					variant={isActive ? 'secondary' : 'primary'}
					onClick={handleEnroll}
					disabled={busy}
				>
					{busy ? (
						<>
							<Loader2 className="h-4 w-4 animate-spin" />
							{state.stage === 'registering' ? 'Waiting for authenticator…' : 'Deriving identity…'}
						</>
					) : isActive ? (
						<>
							<RotateCcw className="h-4 w-4" /> Re-enroll passkey
						</>
					) : (
						<>
							<Fingerprint className="h-4 w-4" /> Use a passkey
						</>
					)}
				</Button>
			</CardContent>
		</Card>
	);
}

function WalletCard({
	importer,
	onReady,
}: {
	importer: StoredMember | null;
	onReady: (m: StoredMember) => void;
}) {
	const wallets = useWallets();
	const isActive = importer?.kind === 'wallet';
	const [busy, setBusy] = React.useState(false);
	const [pickerOpen, setPickerOpen] = React.useState(false);
	const [error, setError] = React.useState<string | null>(null);

	// Wallets that can sign personal messages — what we need to derive a
	// deterministic encryption seed.
	const compatible = React.useMemo(
		() => wallets.filter((w) => w.features.includes('sui:signPersonalMessage')),
		[wallets],
	);

	async function handlePick(wallet: UiWallet) {
		setBusy(true);
		setError(null);
		try {
			// For Enoki wallets, force a fresh OAuth ceremony every time. Their
			// standard:connect short-circuits when an account is already cached,
			// which means picking "Sign in with Google" twice silently returns the
			// same account — we want the user to be able to choose a different
			// Google identity (paired with prompt=select_account in the provider
			// config) without having to manually disconnect first.
			if (isEnokiWallet(wallet) && wallet.accounts.length > 0) {
				await dAppKit.disconnectWallet();
			}
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
			// The importer is the original key uploader — they MUST hold an
			// encryption identity (their share is what gets re-encrypted to other
			// members). Approver-only wallets (zkLogin) can't take this seat.
			if (member.kind !== 'wallet') {
				throw new Error(
					`${wallet.name} doesn't produce a stable signing key, so it can't ` +
						'be the initial user. Use a regular Sui wallet (Sui Wallet, ' +
						'Slush, Phantom, etc.), or a passkey, then add this wallet as ' +
						'an approver-only member on the next step.',
				);
			}
			const stored: StoredMember = {
				kind: 'wallet',
				address: member.address,
				walletName: member.walletName,
				scheme: member.scheme,
				publicKeyHex: member.publicKeyHex,
				encryptionKeysBytesHex: member.encryptionKeysBytesHex,
				encryptionAddress: member.encryptionAddress,
			};
			await saveActiveImporter(storedToCached(stored));
			onReady(stored);
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
		<Card tone="raised" className="p-0 overflow-hidden">
			<div className="px-6 py-4 border-b border-border flex items-baseline justify-between">
				<span className="smallcaps text-text-2 inline-flex items-center gap-1.5">
					<Wallet className="h-3 w-3" />
					Wallet
				</span>
				{isActive && (
					<span className="smallcaps text-sage inline-flex items-center gap-1">
						<CheckCircle2 className="h-3 w-3" /> Active
					</span>
				)}
			</div>
			<CardContent className="p-6 sm:p-7 space-y-5">
				<ol className="space-y-3 text-[14px] text-text-2 leading-[1.6]">
					<Step n="i">
						Connect any Sui wallet that supports{' '}
						<Mono className="text-[12px]">signPersonalMessage</Mono>.
					</Step>
					<Step n="ii">
						The wallet signs a fixed app-scoped message. We hash that signature into a 32-byte
						deterministic seed.
					</Step>
					<Step n="iii">
						The seed derives an Ika encryption identity. The same wallet always derives the same
						identity — so you can re-derive on any device.
					</Step>
				</ol>

				{error && (
					<div className="flex items-start gap-2 text-[13px] text-clay leading-[1.55]">
						<AlertCircle className="h-3.5 w-3.5 mt-[2px] flex-none" />
						{error}
					</div>
				)}

				{!pickerOpen ? (
					<Button
						size="lg"
						variant={isActive ? 'secondary' : 'primary'}
						onClick={() => setPickerOpen(true)}
						disabled={busy}
					>
						{isActive ? (
							<>
								<RotateCcw className="h-4 w-4" /> Switch wallet
							</>
						) : (
							<>
								<Wallet className="h-4 w-4" /> Use a wallet
							</>
						)}
					</Button>
				) : (
					<div className="surface p-2 space-y-1">
						{compatible.length === 0 ? (
							<p className="px-3 py-4 text-[12.5px] text-text-3">
								No Sui wallets detected. Install Slush, Sui Wallet, Phantom, or another
								Sui-compatible wallet, then refresh this page.
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
										{/* For Enoki, the cached address is about to be replaced
                       by a fresh OAuth ceremony — showing it is misleading.
                       Non-Enoki extensions (Slush, Phantom) keep their
                       address since it's stable across the connect call. */}
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
			</CardContent>
		</Card>
	);
}

function ReadyBanner({
	importer,
}: {
	// The importer is gated to key-holders by `handlePick`; re-narrow here so
	// we can read the encryption fields without a runtime branch in JSX.
	importer: Exclude<StoredMember, { kind: 'approver' }>;
}) {
	const label =
		importer.kind === 'passkey'
			? 'Passkey'
			: importer.walletName
				? `Wallet · ${importer.walletName}`
				: 'Wallet';
	const handle =
		importer.kind === 'passkey'
			? `${importer.publicKeyHex.slice(0, 10)}…${importer.publicKeyHex.slice(-6)}`
			: `${importer.address.slice(0, 10)}…${importer.address.slice(-6)}`;
	return (
		<div className="surface mt-4 px-5 py-4 flex flex-wrap items-baseline gap-x-6 gap-y-2">
			<div className="smallcaps text-sage inline-flex items-center gap-1.5">
				<CheckCircle2 className="h-3 w-3" />
				Initial user ready
			</div>
			<div className="flex items-baseline gap-2">
				<span className="smallcaps text-text-3">{label}</span>
				<Mono className="text-[12px]">{handle}</Mono>
			</div>
			<div className="flex items-baseline gap-2">
				<span className="smallcaps text-text-3">enc</span>
				<Mono className="text-[12px]">
					{importer.encryptionAddress.slice(0, 10)}…{importer.encryptionAddress.slice(-6)}
				</Mono>
			</div>
		</div>
	);
}

function Step({ n, children }: { n: string; children: React.ReactNode }) {
	return (
		<li className="flex gap-3">
			<span className="flex-none font-display italic text-[14px] text-clay tabular w-5 mt-[2px]">
				{n}
			</span>
			<span>{children}</span>
		</li>
	);
}
