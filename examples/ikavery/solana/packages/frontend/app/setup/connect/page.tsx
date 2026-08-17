'use client';

import { useDynamicContext } from '@dynamic-labs/sdk-react-core';
import { Button, Card, CardContent, truncateAddress } from '@fesal-packages/ikavery-frontend-ui';
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
	const reset = useSetup((s) => s.reset);
	const [hostname, setHostname] = React.useState('');
	const { primaryWallet, sdkHasLoaded, handleLogOut } = useDynamicContext();

	React.useEffect(() => {
		setHostname(window.location.hostname);
	}, []);

	// Hydrate the setup-store importer from the IDB cache on first mount,
	// so a returning user lands here with their importer already chosen.
	React.useEffect(() => {
		let cancelled = false;
		void (async () => {
			if (importer) return;
			const cached = await loadActiveImporter();
			if (!cancelled && cached) {
				setImporter(cachedToStored(cached));
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [importer, setImporter]);

	// If the user picked the wallet path and Dynamic re-hydrates a primary
	// wallet, reflect that into the importer slot so the wallet card shows
	// "Active". On a passkey importer we leave the wallet untouched — the
	// wallet (if any) is then just the gas-payer for setup, not the identity.
	React.useEffect(() => {
		if (!sdkHasLoaded) return;
		if (importer && importer.kind !== 'wallet') return;
		if (!primaryWallet?.address) return;
		if (importer?.kind === 'wallet' && importer.address === primaryWallet.address) {
			return;
		}
		const stored: StoredMember = {
			kind: 'wallet',
			address: primaryWallet.address,
			walletName: primaryWallet.connector?.name,
		};
		setImporter(stored);
		void saveActiveImporter({
			kind: 'wallet',
			address: stored.address,
			walletName: stored.walletName,
			createdAt: Date.now(),
		});
	}, [primaryWallet, sdkHasLoaded, importer, setImporter]);

	async function handleReset() {
		await clearActiveImporter();
		reset();
		if (primaryWallet) {
			try {
				await handleLogOut();
			} catch {
				/* user cancelled / Dynamic timeout — store reset is enough */
			}
		}
	}

	return (
		<>
			<StepHeader
				ord="01 / Initial user"
				title="Pick your identity"
				italic="for this vault."
				hint="The initial user is whoever runs setup. It can be a passkey (Touch ID, Face ID, hardware key) or any Solana wallet that can sign transactions. The credential you choose here authorises the on-chain Recovery account create and stays as member 0 of the roster."
			/>

			<div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
				<PasskeyCard hostname={hostname} importer={importer} />
				<WalletCard importer={importer} />
			</div>

			{importer && <ReadyBanner importer={importer} />}

			<StepFooter
				hint={
					importer
						? 'Identity cached locally. Reset below to switch.'
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
			label: c.label,
		};
	}
	return {
		kind: 'wallet',
		address: c.address,
		walletName: c.walletName,
	};
}

function PasskeyCard({ hostname, importer }: { hostname: string; importer: StoredMember | null }) {
	const { state, enroll } = usePasskey();
	const setImporter = useSetup((s) => s.setImporter);
	const isActive = importer?.kind === 'passkey';
	const busy = state.stage === 'registering';

	React.useEffect(() => {
		if (state.stage === 'ready' && !isActive) {
			setImporter({
				kind: 'passkey',
				credentialIdHex: state.importer.credentialIdHex,
				publicKeyHex: state.importer.publicKeyHex,
				label: state.importer.label,
			});
		}
	}, [state, isActive, setImporter]);

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
						The credential is constrained to ES256 (secp256r1) so the assertion is verifiable by
						Solana&apos;s native precompile.
					</Step>
					<Step n="iii">
						Every recovery op runs a fresh WebAuthn assertion; the program checks the signature on
						chain via <Mono className="text-[12px]">SCHEME_WEBAUTHN</Mono>.
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
							Waiting for authenticator…
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

function WalletCard({ importer }: { importer: StoredMember | null }) {
	const { primaryWallet, sdkHasLoaded, setShowAuthFlow } = useDynamicContext();
	const isActive = importer?.kind === 'wallet';

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
						Connect any Solana-compatible wallet — Phantom, Backpack, Solflare, hardware, or an
						embedded social login.
					</Step>
					<Step n="ii">
						The connected pubkey is recorded as <Mono className="text-[12px]">member 0</Mono> in the
						on-chain Recovery roster.
					</Step>
					<Step n="iii">
						The same wallet signs the on-chain create &amp; transfer-authority transactions on the
						Review step, and pays Solana fees.
					</Step>
				</ol>

				{!sdkHasLoaded ? (
					<span className="inline-flex items-center gap-2 smallcaps text-text-3">
						<Loader2 className="h-3 w-3 animate-spin" />
						Loading wallet bridge…
					</span>
				) : primaryWallet ? (
					<Button size="lg" variant="secondary" onClick={() => setShowAuthFlow(true)}>
						<RotateCcw className="h-4 w-4" /> Switch wallet
					</Button>
				) : (
					<Button size="lg" variant="primary" onClick={() => setShowAuthFlow(true)}>
						<Wallet className="h-4 w-4" /> Use a wallet
					</Button>
				)}
			</CardContent>
		</Card>
	);
}

function ReadyBanner({ importer }: { importer: StoredMember }) {
	const label =
		importer.kind === 'passkey'
			? 'Passkey'
			: importer.walletName
				? `Wallet · ${importer.walletName}`
				: 'Wallet';
	const handle =
		importer.kind === 'passkey'
			? `${importer.publicKeyHex.slice(0, 10)}…${importer.publicKeyHex.slice(-6)}`
			: truncateAddress(importer.address, 10, 6);
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
