'use client';

import { Card, cn } from '@fesal-packages/ikavery-frontend-ui';
import { useCurrentAccount, useWalletConnection, useWallets } from '@mysten/dapp-kit-react';
import { parseSerializedSignature } from '@mysten/sui/cryptography';
import { fromHex, normalizeSuiAddress } from '@mysten/sui/utils';
import {
	AlertCircle,
	CheckCircle2,
	ChevronDown,
	ChevronUp,
	Fingerprint,
	Loader2,
	Lock,
	Wallet,
	X,
} from 'lucide-react';
import * as React from 'react';

import { GasBudgetRow } from '@/components/vault/gas-budget-row';
import { WalletConnect } from '@/components/wallet-connect';
import type { CostEstimate } from '@/lib/gas-preflight';
import { findMember, type Scheme, type VaultMember, type VaultState } from '@/lib/recovery-state';
import type { GasPayer } from '@/lib/sponsored-sign';
import { hexToBytes, loadActiveImporter, type CachedImporter } from '@/lib/storage';

/**
 * The on-device identity that authorizes an action on this vault. Sui's tx
 * signature only proves who paid gas (ctx.sender); auth is verified
 * separately in Move via the credential — `auth::verify` checks a member's
 * signature over a per-operation challenge against the unified members set.
 *
 *  - `passkey`: WebAuthn ceremony on this device.
 *  - `wallet`:  member wallet's `signPersonalMessage` over the challenge.
 *  - `approver`: scheme `sender_address`. Auth IS the tx signature, so the
 *    gas-payer wallet MUST be this approver's address.
 */
export type SignerOption =
	| {
			kind: 'passkey';
			importer: Extract<CachedImporter, { kind: 'passkey' }>;
			member: VaultMember;
	  }
	| {
			kind: 'wallet';
			scheme: Exclude<Scheme, 'webauthn' | 'sender_address'>;
			address: string;
			walletName: string;
			walletIcon?: string;
			member: VaultMember;
	  }
	| {
			kind: 'approver';
			address: string;
			walletName: string;
			walletIcon?: string;
			member: VaultMember;
	  };

export type SignerState = {
	options: SignerOption[];
	active: SignerOption | null;
	/** All connected wallet accounts that could be picked as gas-payer. */
	gasPayerOptions: GasPayer[];
	gasPayer: GasPayer | null;
	/**
	 * Approver-only signers force the gas-payer to that approver's wallet —
	 * the picker is hidden in that case (no choice to make).
	 */
	gasLocked: boolean;
	ready: boolean;
	/**
	 * dapp-kit is still re-attaching the previously-connected wallet
	 * (`autoConnect` runs after mount). UI should defer to this and render
	 * "Reconnecting…" rather than a "Connect wallet" CTA — refreshing the page
	 * does not actually disconnect the user.
	 */
	reconnecting: boolean;
};

export function useSignerState(vault: VaultState | undefined): {
	state: SignerState;
	pickSigner: (option: SignerOption) => void;
	pickGas: (gp: GasPayer) => void;
} {
	const account = useCurrentAccount();
	const wallets = useWallets();
	const { isConnecting } = useWalletConnection();
	const [cachedImporter, setCachedImporter] = React.useState<CachedImporter | null>(null);
	const [picked, setPicked] = React.useState<SignerOption | null>(null);
	const [pickedGasAddr, setPickedGasAddr] = React.useState<string | null>(null);
	const [walletScheme, setWalletScheme] = React.useState<Scheme | null>(null);

	React.useEffect(() => {
		void loadActiveImporter().then(setCachedImporter);
	}, []);

	// Connecting wallets advertise raw `account.publicKey` but no signature
	// scheme, so we infer it: 32 bytes ⇒ ed25519, 33 bytes ⇒ secp256k1 OR r1.
	// The cached importer is the disambiguator when present (same wallet that
	// enrolled gives us the scheme verbatim). Fall back to ed25519 when we
	// can't tell — the on-chain match will fail loudly if it's wrong.
	React.useEffect(() => {
		if (!account) {
			setWalletScheme(null);
			return;
		}
		if (
			cachedImporter?.kind === 'wallet' &&
			cachedImporter.address.toLowerCase() === account.address.toLowerCase()
		) {
			setWalletScheme(cachedImporter.scheme);
			return;
		}
		if (account.publicKey.length === 32) setWalletScheme('ed25519');
		else if (account.publicKey.length === 33) setWalletScheme('secp256k1');
		else setWalletScheme(null);
	}, [account, cachedImporter]);

	const options: SignerOption[] = React.useMemo(() => {
		if (!vault) return [];
		const out: SignerOption[] = [];

		if (cachedImporter && cachedImporter.kind === 'passkey') {
			const matched = findMember(vault, 'webauthn', hexToBytes(cachedImporter.publicKeyHex));
			if (matched) {
				out.push({
					kind: 'passkey',
					importer: cachedImporter,
					member: matched,
				});
			}
		}

		if (
			account &&
			walletScheme &&
			walletScheme !== 'webauthn' &&
			walletScheme !== 'sender_address'
		) {
			const matched = findMember(vault, walletScheme, new Uint8Array(account.publicKey));
			if (matched) {
				const wallet = wallets.find((w) =>
					w.accounts.some((a) => a.address.toLowerCase() === account.address.toLowerCase()),
				);
				out.push({
					kind: 'wallet',
					scheme: walletScheme,
					address: account.address,
					walletName: wallet?.name ?? 'Wallet',
					walletIcon: wallet?.icon,
					member: matched,
				});
			}
		}

		// Approver-only membership: the connected wallet's address itself is
		// the member id. Auth is by ctx.sender match — Sui's tx validator
		// verifies whatever signature scheme the wallet used (zkLogin in
		// practice), Move just confirms the sender is in the members set.
		if (account) {
			const addrBytes = fromHex(normalizeSuiAddress(account.address).slice(2));
			const matched = findMember(vault, 'sender_address', addrBytes);
			if (matched) {
				const wallet = wallets.find((w) =>
					w.accounts.some((a) => a.address.toLowerCase() === account.address.toLowerCase()),
				);
				out.push({
					kind: 'approver',
					address: account.address,
					walletName: wallet?.name ?? 'Wallet',
					walletIcon: wallet?.icon,
					member: matched,
				});
			}
		}

		return out;
	}, [cachedImporter, account, walletScheme, vault, wallets]);

	const active = React.useMemo<SignerOption | null>(() => {
		if (picked) {
			const stillThere = options.find((o) => sameOption(o, picked));
			if (stillThere) return stillThere;
		}
		return options[0] ?? null;
	}, [picked, options]);

	// Every connected (wallet, account) pair becomes a gas-payer candidate.
	// Approver-only signers narrow this down to the approver's wallet only.
	const gasPayerOptions: GasPayer[] = React.useMemo(() => {
		const out: GasPayer[] = [];
		for (const w of wallets) {
			for (const a of w.accounts) {
				out.push({
					wallet: w,
					account: a,
					walletName: w.name,
					walletIcon: w.icon,
					address: a.address,
				});
			}
		}
		return out;
	}, [wallets]);

	// Constraint: an approver credential is valid only if ctx.sender ==
	// approver.address. So when an approver is the active signer, the gas
	// payer is forced to that account — no choice to make.
	const gasLocked = active?.kind === 'approver';

	const gasPayer = React.useMemo<GasPayer | null>(() => {
		if (gasLocked && active && active.kind === 'approver') {
			const forced = gasPayerOptions.find(
				(o) => o.address.toLowerCase() === active.address.toLowerCase(),
			);
			if (forced) return forced;
		}
		if (pickedGasAddr) {
			const stillThere = gasPayerOptions.find(
				(o) => o.address.toLowerCase() === pickedGasAddr.toLowerCase(),
			);
			if (stillThere) return stillThere;
		}
		// Default: prefer the credential wallet's own account (signer == gas
		// payer is the most common case), else the dapp-kit "current" account,
		// else the first available.
		if (active?.kind === 'wallet') {
			const sameWallet = gasPayerOptions.find(
				(o) => o.address.toLowerCase() === active.address.toLowerCase(),
			);
			if (sameWallet) return sameWallet;
		}
		if (account) {
			const cur = gasPayerOptions.find(
				(o) => o.address.toLowerCase() === account.address.toLowerCase(),
			);
			if (cur) return cur;
		}
		return gasPayerOptions[0] ?? null;
	}, [gasLocked, active, pickedGasAddr, gasPayerOptions, account]);

	const ready = !!active && !!gasPayer;

	return {
		state: {
			options,
			active,
			gasPayerOptions,
			gasPayer,
			gasLocked,
			ready,
			reconnecting: isConnecting,
		},
		pickSigner: setPicked,
		pickGas: (gp: GasPayer) => setPickedGasAddr(gp.address),
	};
}

export function SignerGasPayerCard({
	vault,
	state,
	onPickSigner,
	onPickGas,
	estimate,
}: {
	vault: VaultState;
	state: SignerState;
	onPickSigner: (option: SignerOption) => void;
	onPickGas: (gp: GasPayer) => void;
	/**
	 * Required SUI + IKA for the action this card guards (propose / approve /
	 * execute). Renders a "have vs need" row underneath the gas-payer so the
	 * user notices a low balance before the wallet prompt.
	 */
	estimate: CostEstimate;
}) {
	const { options, active, gasPayer, gasPayerOptions, gasLocked, ready, reconnecting } = state;
	const account = useCurrentAccount();
	const memberCount = vault.members.length;

	// No signing identity at all → either no wallet connected, or the connected
	// wallet isn't a member. Surface the difference explicitly. While dapp-kit
	// is still re-attaching the previously-connected wallet, render a soft
	// "Reconnecting…" instead of the "Connect a wallet" CTA — otherwise a
	// refresh flashes a misleading prompt.
	if (options.length === 0) {
		return (
			<Card tone="raised" className="p-0 overflow-visible">
				<div className="px-5 sm:px-8 py-3 border-b border-border">
					<span className="smallcaps text-text-3">Signer</span>
				</div>
				<div className="px-5 sm:px-8 py-5">
					{reconnecting && !account ? (
						<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
							<Loader2 className="h-3 w-3 animate-spin" />
							Reconnecting wallet…
						</span>
					) : !account ? (
						<div className="flex flex-col sm:flex-row sm:items-center gap-3">
							<div className="flex-1 text-[13.5px] text-text-2 leading-[1.55]">
								Connect a wallet that&apos;s in the {memberCount}-member roster, or open this page
								on the device that holds an enrolled passkey.
							</div>
							<WalletConnect />
						</div>
					) : (
						<div className="flex items-start gap-3">
							<AlertCircle className="h-4 w-4 text-clay mt-0.5 flex-none" />
							<div className="text-[13.5px] text-text-2 leading-[1.55]">
								<div className="font-mono text-[12.5px] tabular text-text mb-1">
									{truncate(account.address)}
								</div>
								<p>
									This wallet isn&apos;t one of the {memberCount} vault members. Switch wallets to a
									member, or open this page on a device that has an enrolled passkey member.
								</p>
							</div>
						</div>
					)}
				</div>
			</Card>
		);
	}

	return (
		<Card tone="raised" className="p-0 overflow-visible">
			<div className="px-5 sm:px-8 py-3 border-b border-border flex items-center justify-between">
				<span className="smallcaps text-text-3">Signer + gas</span>
				{ready && (
					<span className="smallcaps text-sage inline-flex items-center gap-1">
						<CheckCircle2 className="h-3 w-3" />
						Ready
					</span>
				)}
			</div>

			{/* Signer (credential) */}
			<div className="px-5 sm:px-8 py-5 flex flex-col gap-3">
				<div className="smallcaps text-text-3">Auth identity</div>
				{options.length === 1 ? (
					<SignerReadout option={options[0]!} />
				) : (
					<div className="grid gap-2 grid-cols-1 sm:grid-cols-2">
						{options.map((o) => (
							<SignerRow
								key={
									o.kind === 'passkey'
										? `pk:${o.importer.publicKeyHex}`
										: o.kind === 'approver'
											? `approver:${o.address}`
											: `wallet:${o.scheme}:${o.address}`
								}
								option={o}
								active={active != null && sameOption(o, active)}
								onPick={() => onPickSigner(o)}
							/>
						))}
					</div>
				)}
			</div>

			{/* Gas payer (= ctx.sender, pays SUI gas + IKA fees) */}
			<div className="px-5 sm:px-8 py-4 border-t border-border flex flex-col gap-3">
				<GasSection
					gasPayer={gasPayer}
					options={gasPayerOptions}
					locked={gasLocked}
					reconnecting={reconnecting}
					onPickGas={onPickGas}
				/>
				<GasBudgetRow gasPayerAddress={gasPayer?.address ?? null} estimate={estimate} />
			</div>

			{/* Prompt-count hint */}
			{ready && active && gasPayer && (
				<div className="px-5 sm:px-8 py-3 border-t border-border bg-surface-3/40">
					<PromptCountHint signer={active} gasPayer={gasPayer} />
				</div>
			)}
		</Card>
	);
}

// ===== inner sections =====

function SignerReadout({ option }: { option: SignerOption }) {
	const Icon = option.kind === 'passkey' ? Fingerprint : Wallet;
	const handle =
		option.kind === 'passkey' ? truncate(option.importer.publicKeyHex) : truncate(option.address);
	const sub =
		option.kind === 'passkey'
			? 'Passkey · this device'
			: option.kind === 'approver'
				? `Approver-only · ${option.walletName}`
				: `${option.scheme} · ${option.walletName}`;
	return (
		<div className="flex items-center gap-3 px-4 py-3 rounded-md bg-clay/[0.06] border border-clay/40">
			<div className="h-8 w-8 flex-none rounded border border-clay/40 bg-clay/15 text-clay flex items-center justify-center">
				<Icon className="h-3.5 w-3.5" />
			</div>
			<div className="flex-1 min-w-0">
				<div className="font-mono text-[12.5px] tabular text-text truncate break-normal">
					{handle}
				</div>
				<div className="smallcaps text-text-3 mt-1">{sub}</div>
			</div>
		</div>
	);
}

function SignerRow({
	option,
	active,
	onPick,
}: {
	option: SignerOption;
	active: boolean;
	onPick: () => void;
}) {
	const Icon = option.kind === 'passkey' ? Fingerprint : Wallet;
	const handle =
		option.kind === 'passkey' ? truncate(option.importer.publicKeyHex) : truncate(option.address);
	const sub =
		option.kind === 'passkey'
			? 'Passkey · this device'
			: option.kind === 'approver'
				? `Approver-only · ${option.walletName}`
				: `${option.scheme} · ${option.walletName}`;
	return (
		<button
			type="button"
			onClick={onPick}
			className={cn(
				'text-left flex items-center gap-3 px-4 py-3 rounded-md border transition-colors',
				active ? 'bg-clay/[0.06] border-clay/40' : 'border-border hover:bg-surface-3/60',
			)}
		>
			<div
				className={cn(
					'h-8 w-8 flex-none rounded border flex items-center justify-center',
					active ? 'bg-clay/15 border-clay/40 text-clay' : 'bg-surface-2 border-border text-text-3',
				)}
			>
				<Icon className="h-3.5 w-3.5" />
			</div>
			<div className="flex-1 min-w-0">
				<div className="font-mono text-[12.5px] tabular text-text truncate break-normal">
					{handle}
				</div>
				<div className="smallcaps text-text-3 mt-1 flex items-center gap-1.5 flex-wrap">
					<span>{sub}</span>
					{active && (
						<span className="text-sage inline-flex items-center gap-1">
							<CheckCircle2 className="h-3 w-3" />
							Active
						</span>
					)}
				</div>
			</div>
		</button>
	);
}

function GasSection({
	gasPayer,
	options,
	locked,
	reconnecting,
	onPickGas,
}: {
	gasPayer: GasPayer | null;
	options: GasPayer[];
	locked: boolean;
	reconnecting: boolean;
	onPickGas: (gp: GasPayer) => void;
}) {
	const [picking, setPicking] = React.useState(false);

	if (!gasPayer) {
		if (reconnecting) {
			return (
				<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<Loader2 className="h-3 w-3 animate-spin" />
					Reconnecting wallet…
				</span>
			);
		}
		return (
			<span className="text-[13px] text-text-3 leading-[1.55]">Connect a wallet to pay gas.</span>
		);
	}

	// When auth is locked to ctx.sender (approver), the gas-payer is fixed.
	// Otherwise the user can either pick a different connected account or
	// connect a new wallet — both exposed via the picker.
	const canSwitch = !locked;

	return (
		<div className="flex flex-col gap-3">
			<div className="flex items-center justify-between gap-2">
				<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<Wallet className="h-3 w-3" />
					Gas payer (ctx.sender · pays SUI + IKA)
				</span>
				{canSwitch ? (
					<button
						type="button"
						onClick={() => setPicking((p) => !p)}
						className="smallcaps text-clay inline-flex items-center gap-1 hover:underline"
					>
						Change wallet
						{picking ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
					</button>
				) : null}
			</div>

			<div
				className={cn(
					'flex items-center gap-2 px-3 py-2 rounded-md border',
					locked ? 'bg-clay/[0.04] border-clay/30' : 'bg-surface-3/40 border-border',
				)}
			>
				{gasPayer.walletIcon && (
					// eslint-disable-next-line @next/next/no-img-element
					<img src={gasPayer.walletIcon} alt="" className="h-4 w-4 rounded-sm flex-none" />
				)}
				<span className="font-mono text-[12.5px] tabular text-text truncate break-normal">
					{gasPayer.address}
				</span>
				<span className="smallcaps text-text-4 ml-auto inline-flex items-center gap-1">
					{locked && <Lock className="h-3 w-3" />}
					{gasPayer.walletName}
				</span>
			</div>

			{locked && (
				<span className="text-[12px] text-text-4 leading-[1.5]">
					Approver-only signer authenticates by ctx.sender match — gas-payer must be this same
					wallet.
				</span>
			)}

			{canSwitch && picking && (
				<div className="rounded-md border border-border bg-surface-2 p-2 flex flex-col gap-1">
					<div className="px-2 py-1 flex items-center justify-between">
						<span className="smallcaps text-text-3">Pick a connected wallet</span>
						<button
							type="button"
							onClick={() => setPicking(false)}
							className="text-text-3 hover:text-text"
							aria-label="Close picker"
						>
							<X className="h-3.5 w-3.5" />
						</button>
					</div>
					{options.map((o) => {
						const isCurrent = o.address.toLowerCase() === gasPayer.address.toLowerCase();
						return (
							<button
								key={`${o.walletName}:${o.address}`}
								type="button"
								onClick={() => {
									onPickGas(o);
									setPicking(false);
								}}
								className={cn(
									'text-left flex items-center gap-3 px-3 py-2 rounded-md border transition-colors',
									isCurrent
										? 'bg-clay/[0.06] border-clay/40'
										: 'border-transparent hover:bg-surface-3/60 hover:border-border',
								)}
							>
								{o.walletIcon && (
									// eslint-disable-next-line @next/next/no-img-element
									<img src={o.walletIcon} alt="" className="h-4 w-4 rounded-sm flex-none" />
								)}
								<div className="flex-1 min-w-0">
									<div className="font-mono text-[12.5px] tabular text-text truncate break-normal">
										{o.address}
									</div>
									<div className="smallcaps text-text-3 mt-0.5 inline-flex items-center gap-1.5">
										<span>{o.walletName}</span>
										{isCurrent && (
											<span className="text-sage inline-flex items-center gap-1">
												<CheckCircle2 className="h-3 w-3" />
												Active
											</span>
										)}
									</div>
								</div>
							</button>
						);
					})}
					<div className="mt-1 px-2 py-2 border-t border-border flex items-center justify-between gap-2">
						<span className="text-[12px] text-text-3 leading-[1.5]">Need a different account?</span>
						<WalletConnect align="end" />
					</div>
				</div>
			)}
		</div>
	);
}

function PromptCountHint({ signer, gasPayer }: { signer: SignerOption; gasPayer: GasPayer }) {
	// Approver: auth IS the tx signature itself (ctx.sender match) → 1 prompt.
	// Passkey: ceremony on this device + tx sig → 2 prompts.
	// Wallet member: personal-msg sig + tx sig. If credential wallet == gas
	//   wallet, that's 2 prompts on the same wallet (Slush will batch a bit
	//   visually, but it's still two confirmations). If credential wallet ≠
	//   gas wallet, still 2 prompts (one each), but on different wallets.
	const isApprover = signer.kind === 'approver';
	const isPasskey = signer.kind === 'passkey';
	const credAndGasSame =
		signer.kind === 'wallet'
			? signer.address.toLowerCase() === gasPayer.address.toLowerCase()
			: false;
	if (isApprover) {
		return (
			<span className="text-[12px] text-text-3 leading-[1.5]">
				<span className="text-text-2 font-medium">1 confirmation:</span> tx signature (
				{gasPayer.walletName}).
			</span>
		);
	}
	const parts: string[] = [];
	parts.push(
		isPasskey
			? 'passkey ceremony'
			: credAndGasSame
				? `${gasPayer.walletName} personal-msg`
				: `credential wallet personal-msg`,
	);
	parts.push(`tx signature (${gasPayer.walletName})`);
	return (
		<span className="text-[12px] text-text-3 leading-[1.5]">
			<span className="text-text-2 font-medium">2 confirmations:</span> {parts.join(', then ')}.
		</span>
	);
}

// ===== helpers =====

function sameOption(a: SignerOption, b: SignerOption): boolean {
	if (a.kind !== b.kind) return false;
	if (a.kind === 'passkey' && b.kind === 'passkey') {
		return a.importer.publicKeyHex === b.importer.publicKeyHex;
	}
	if (a.kind === 'wallet' && b.kind === 'wallet') {
		return a.scheme === b.scheme && a.address.toLowerCase() === b.address.toLowerCase();
	}
	if (a.kind === 'approver' && b.kind === 'approver') {
		return a.address.toLowerCase() === b.address.toLowerCase();
	}
	return false;
}

function truncate(s: string, head = 14, tail = 8): string {
	if (s.length <= head + tail + 1) return s;
	return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

// Re-export for callers that need to peel a wallet's wrapped sig (auth flows).
export { parseSerializedSignature };
