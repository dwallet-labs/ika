'use client';

import { useDynamicContext, useUserWallets, type Wallet } from '@dynamic-labs/sdk-react-core';
import { isSolanaWallet } from '@dynamic-labs/solana';
import { Card, cn } from '@fesal-packages/ikavery-frontend-ui';
import {
	memberIdBytes,
	packMemberSlot,
	packSolanaMember,
	SCHEME_WEBAUTHN,
} from '@fesal-packages/ikavery-solana-sdk';
import { PublicKey } from '@solana/web3.js';
import {
	AlertCircle,
	CheckCircle2,
	ChevronDown,
	ChevronUp,
	Fingerprint,
	Loader2,
	Lock,
	Wallet as WalletIcon,
	X,
} from 'lucide-react';
import * as React from 'react';

import WalletConnectImpl from '@/components/wallet-connect-impl';
import { hexToBytes, loadActiveImporter, type CachedImporter } from '@/lib/storage';
import type { StoredMember } from '@/store/setup';

/**
 * The on-device identity that authorizes an action on this vault.
 *
 * Two modes today:
 *  - `passkey`: WebAuthn assertion + secp256r1 precompile. Decoupled from
 *     the tx fee-payer.
 *  - `wallet`: SCHEME_SOLANA_ADDRESS. The on-chain check requires the
 *     credential's address to be the tx Signer — so the gas-payer is
 *     locked to that wallet (Solana's analog of Sui's `approver`).
 */
export type SignerOption =
	| {
			kind: 'passkey';
			importer: Extract<CachedImporter, { kind: 'passkey' }>;
			memberSlot: Uint8Array;
	  }
	| {
			kind: 'wallet';
			address: string;
			walletName: string;
			walletIcon?: string;
			memberSlot: Uint8Array;
	  };

export interface GasPayer {
	wallet: Wallet;
	address: string;
	walletName: string;
	walletIcon?: string;
}

export interface SignerState {
	options: SignerOption[];
	active: SignerOption | null;
	gasPayerOptions: GasPayer[];
	gasPayer: GasPayer | null;
	/**
	 * True when the active signer is a wallet member — gas-payer is forced
	 * to the same wallet because SCHEME_SOLANA_ADDRESS verifies via tx
	 * Signer match on chain.
	 */
	gasLocked: boolean;
	ready: boolean;
	/** Dynamic is still re-attaching the previous session. */
	reconnecting: boolean;
}

interface RosterShape {
	members: Uint8Array[];
}

export function useSignerState(roster: RosterShape | undefined | null): {
	state: SignerState;
	pickSigner: (option: SignerOption) => void;
	pickGas: (gp: GasPayer) => void;
	/**
	 * Translate the active signer into the legacy `StoredMember` shape used
	 * by produceAuth + the lib functions.
	 */
	voterFromActive: () => StoredMember | null;
} {
	const { sdkHasLoaded } = useDynamicContext();
	const wallets = useUserWallets();
	const [cachedImporter, setCachedImporter] = React.useState<CachedImporter | null>(null);
	const [picked, setPicked] = React.useState<SignerOption | null>(null);
	const [pickedGasAddr, setPickedGasAddr] = React.useState<string | null>(null);

	React.useEffect(() => {
		void loadActiveImporter().then(setCachedImporter);
	}, []);

	const solanaWallets = React.useMemo(
		() => wallets.filter((w): w is Wallet => isSolanaWallet(w)),
		[wallets],
	);

	const options: SignerOption[] = React.useMemo(() => {
		if (!roster) return [];
		const out: SignerOption[] = [];
		const rosterIds = roster.members.map((slot) => bytesToHex(memberIdBytes(slot)));

		if (cachedImporter && cachedImporter.kind === 'passkey') {
			const slot = packMemberSlot(SCHEME_WEBAUTHN, hexToBytes(cachedImporter.publicKeyHex));
			const id = bytesToHex(memberIdBytes(slot));
			if (rosterIds.includes(id)) {
				out.push({
					kind: 'passkey',
					importer: cachedImporter,
					memberSlot: slot,
				});
			}
		}

		for (const w of solanaWallets) {
			try {
				const slot = packSolanaMember(new PublicKey(w.address));
				const id = bytesToHex(memberIdBytes(slot));
				if (!rosterIds.includes(id)) continue;
				const already = out.some((o) => o.kind === 'wallet' && o.address === w.address);
				if (already) continue;
				out.push({
					kind: 'wallet',
					address: w.address,
					walletName: walletDisplayName(w),
					walletIcon: walletIcon(w),
					memberSlot: slot,
				});
			} catch {
				// bad base58 — skip
			}
		}

		return out;
	}, [roster, cachedImporter, solanaWallets]);

	const active = React.useMemo<SignerOption | null>(() => {
		if (picked) {
			const stillThere = options.find((o) => sameSigner(o, picked));
			if (stillThere) return stillThere;
		}
		return options[0] ?? null;
	}, [picked, options]);

	const gasPayerOptions: GasPayer[] = React.useMemo(
		() =>
			solanaWallets.map((w) => ({
				wallet: w,
				address: w.address,
				walletName: walletDisplayName(w),
				walletIcon: walletIcon(w),
			})),
		[solanaWallets],
	);

	const gasLocked = active?.kind === 'wallet';

	const gasPayer = React.useMemo<GasPayer | null>(() => {
		if (gasLocked && active?.kind === 'wallet') {
			const forced = gasPayerOptions.find((o) => o.address === active.address);
			if (forced) return forced;
			return null;
		}
		if (pickedGasAddr) {
			const stillThere = gasPayerOptions.find((o) => o.address === pickedGasAddr);
			if (stillThere) return stillThere;
		}
		return gasPayerOptions[0] ?? null;
	}, [gasLocked, active, pickedGasAddr, gasPayerOptions]);

	const ready = !!active && !!gasPayer;

	return {
		state: {
			options,
			active,
			gasPayerOptions,
			gasPayer,
			gasLocked,
			ready,
			reconnecting: !sdkHasLoaded,
		},
		pickSigner: setPicked,
		pickGas: (gp) => setPickedGasAddr(gp.address),
		voterFromActive: () => (active ? signerToStoredMember(active) : null),
	};
}

export function SignerGasPayerCard({
	state,
	onPickSigner,
	onPickGas,
	rosterSize,
}: {
	state: SignerState;
	onPickSigner: (option: SignerOption) => void;
	onPickGas: (gp: GasPayer) => void;
	rosterSize: number;
}) {
	const { options, active, gasPayer, gasPayerOptions, gasLocked, ready, reconnecting } = state;

	if (options.length === 0) {
		return (
			<Card tone="raised" className="p-0 overflow-visible">
				<div className="px-5 sm:px-8 py-3 border-b border-border">
					<span className="smallcaps text-text-3">Signer</span>
				</div>
				<div className="px-5 sm:px-8 py-5">
					{reconnecting && gasPayerOptions.length === 0 ? (
						<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
							<Loader2 className="h-3 w-3 animate-spin" />
							Reconnecting wallet…
						</span>
					) : gasPayerOptions.length === 0 ? (
						<div className="flex flex-col sm:flex-row sm:items-center gap-3">
							<div className="flex-1 text-[13.5px] text-text-2 leading-[1.55]">
								Connect a wallet that&apos;s in the {rosterSize}-member roster, or open this page on
								the device that holds an enrolled passkey.
							</div>
							<WalletConnectImpl />
						</div>
					) : (
						<div className="flex items-start gap-3">
							<AlertCircle className="h-4 w-4 text-clay mt-0.5 flex-none" />
							<div className="text-[13.5px] text-text-2 leading-[1.55]">
								<div className="font-mono text-[12.5px] tabular text-text mb-1">
									{truncate(gasPayerOptions[0]?.address ?? '')}
								</div>
								<p>
									This wallet isn&apos;t one of the {rosterSize} vault members. Switch wallets to a
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

			<div className="px-5 sm:px-8 py-5 flex flex-col gap-3">
				<div className="smallcaps text-text-3">Auth identity</div>
				{options.length === 1 ? (
					<SignerReadout option={options[0] as SignerOption} />
				) : (
					<div className="grid gap-2 grid-cols-1 sm:grid-cols-2">
						{options.map((o) => (
							<SignerRow
								key={signerKey(o)}
								option={o}
								active={active != null && sameSigner(o, active)}
								onPick={() => onPickSigner(o)}
							/>
						))}
					</div>
				)}
			</div>

			<div className="px-5 sm:px-8 py-4 border-t border-border flex flex-col gap-3">
				<GasSection
					gasPayer={gasPayer}
					options={gasPayerOptions}
					locked={gasLocked}
					reconnecting={reconnecting}
					onPickGas={onPickGas}
				/>
			</div>

			{ready && active && gasPayer && (
				<div className="px-5 sm:px-8 py-3 border-t border-border bg-surface-3/40">
					<PromptCountHint signer={active} gasPayer={gasPayer} />
				</div>
			)}
		</Card>
	);
}

function SignerReadout({ option }: { option: SignerOption }) {
	const Icon = option.kind === 'passkey' ? Fingerprint : WalletIcon;
	const handle =
		option.kind === 'passkey' ? truncate(option.importer.publicKeyHex) : truncate(option.address);
	const sub =
		option.kind === 'passkey' ? 'Passkey · this device' : `Solana wallet · ${option.walletName}`;
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
	const Icon = option.kind === 'passkey' ? Fingerprint : WalletIcon;
	const handle =
		option.kind === 'passkey' ? truncate(option.importer.publicKeyHex) : truncate(option.address);
	const sub =
		option.kind === 'passkey' ? 'Passkey · this device' : `Solana wallet · ${option.walletName}`;
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
			<div className="flex flex-col sm:flex-row sm:items-center gap-3">
				<span className="text-[13px] text-text-3 leading-[1.55] flex-1">
					Connect a wallet to pay gas.
				</span>
				<WalletConnectImpl />
			</div>
		);
	}

	const canSwitch = !locked && options.length > 0;

	return (
		<div className="flex flex-col gap-3">
			<div className="flex items-center justify-between gap-2">
				<span className="smallcaps text-text-3 inline-flex items-center gap-1.5">
					<WalletIcon className="h-3 w-3" />
					Gas payer (pays Solana fees)
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
					Wallet member auth verifies via tx Signer match on chain — gas-payer must be this same
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
						const isCurrent = o.address === gasPayer.address;
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
						<WalletConnectImpl align="end" />
					</div>
				</div>
			)}
		</div>
	);
}

function PromptCountHint({ signer, gasPayer }: { signer: SignerOption; gasPayer: GasPayer }) {
	if (signer.kind === 'wallet') {
		return (
			<span className="text-[12px] text-text-3 leading-[1.5]">
				<span className="text-text-2 font-medium">1 confirmation:</span> tx signature (
				{gasPayer.walletName}).
			</span>
		);
	}
	return (
		<span className="text-[12px] text-text-3 leading-[1.5]">
			<span className="text-text-2 font-medium">2 confirmations:</span> passkey ceremony, then tx
			signature ({gasPayer.walletName}).
		</span>
	);
}

function signerToStoredMember(o: SignerOption): StoredMember {
	if (o.kind === 'passkey') {
		return {
			kind: 'passkey',
			credentialIdHex: o.importer.credentialIdHex,
			publicKeyHex: o.importer.publicKeyHex,
			label: o.importer.label,
		};
	}
	return {
		kind: 'wallet',
		address: o.address,
		walletName: o.walletName,
	};
}

function sameSigner(a: SignerOption, b: SignerOption): boolean {
	if (a.kind !== b.kind) return false;
	if (a.kind === 'passkey' && b.kind === 'passkey') {
		return a.importer.publicKeyHex === b.importer.publicKeyHex;
	}
	if (a.kind === 'wallet' && b.kind === 'wallet') {
		return a.address === b.address;
	}
	return false;
}

function signerKey(o: SignerOption): string {
	return o.kind === 'passkey' ? `pk:${o.importer.publicKeyHex}` : `wallet:${o.address}`;
}

function walletDisplayName(w: Wallet): string {
	const conn = (w as unknown as { connector?: { name?: string } }).connector;
	return conn?.name ?? 'Wallet';
}

function walletIcon(w: Wallet): string | undefined {
	const conn = (
		w as unknown as {
			connector?: { metadata?: { icon?: string }; icon?: string };
		}
	).connector;
	return conn?.metadata?.icon ?? conn?.icon;
}

function bytesToHex(b: Uint8Array): string {
	return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function truncate(s: string, head = 14, tail = 8): string {
	if (s.length <= head + tail + 1) return s;
	return `${s.slice(0, head)}…${s.slice(-tail)}`;
}
