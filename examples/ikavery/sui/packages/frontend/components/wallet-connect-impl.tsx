'use client';

import { Button, cn } from '@fesal-packages/ikavery-frontend-ui';
import { useCurrentAccount, useWalletConnection, useWallets } from '@mysten/dapp-kit-react';
import { isEnokiWallet } from '@mysten/enoki';
import { Check, ChevronDown, Loader2, Wallet, X } from 'lucide-react';
import * as React from 'react';

import { dAppKit } from '@/lib/dapp-kit';

function truncate(addr: string, head = 6, tail = 4) {
	if (addr.length <= head + tail + 1) return addr;
	return `${addr.slice(0, head)}…${addr.slice(-tail)}`;
}

function isUserCancelled(message: string): boolean {
	const m = message.toLowerCase();
	return (
		m.includes('reject') ||
		m.includes('cancel') ||
		m.includes('denied') ||
		m.includes('popup closed') ||
		m.includes('user closed')
	);
}

export default function WalletConnectImpl({
	align = 'end',
}: {
	/**
	 * Where the popover anchors relative to the trigger. `"end"` (the default)
	 * pins the popover's right edge to the trigger's right edge — popover
	 * extends leftward, correct when the trigger sits at the right of the
	 * viewport (page header). `"start"` pins the left edges and extends
	 * rightward — use when the trigger lives in a left-side card.
	 */
	align?: 'start' | 'end';
} = {}) {
	const account = useCurrentAccount();
	const wallets = useWallets();
	// autoConnect re-attaches the previously-connected wallet asynchronously
	// after mount; useCurrentAccount() is null during that window. Use the
	// connection-status hook to render a "Reconnecting…" state instead of a
	// "Connect wallet" CTA, which is what the user actually sees on refresh.
	const { isConnecting } = useWalletConnection();
	const connect = dAppKit.connectWallet;
	const disconnect = dAppKit.disconnectWallet;
	const [open, setOpen] = React.useState(false);
	const [copied, setCopied] = React.useState(false);
	const [connectError, setConnectError] = React.useState<string | null>(null);
	const popRef = React.useRef<HTMLDivElement>(null);
	const connectingRef = React.useRef(false);
	const anchorClass = align === 'end' ? 'right-0' : 'left-0';

	// Enoki/zkLogin entries (Sign in with Google, Twitch, Facebook) go on top —
	// they're the most accessible option for users without a wallet extension.
	const sortedWallets = React.useMemo(() => {
		const enoki = wallets.filter(isEnokiWallet);
		const others = wallets.filter((w) => !isEnokiWallet(w));
		return [...enoki, ...others];
	}, [wallets]);

	React.useEffect(() => {
		function onDoc(e: MouseEvent) {
			// Don't dismiss while a connect is in flight — clicking back to the
			// page after a wallet's extension popup goes away counts as "outside."
			if (connectingRef.current) return;
			if (popRef.current && !popRef.current.contains(e.target as Node)) {
				setOpen(false);
			}
		}
		if (open) document.addEventListener('mousedown', onDoc);
		return () => document.removeEventListener('mousedown', onDoc);
	}, [open]);

	if (account) {
		return (
			<div className="relative inline-block w-fit" ref={popRef}>
				<button
					type="button"
					onClick={() => setOpen((v) => !v)}
					className={cn(
						'inline-flex items-center gap-2 h-9 px-3',
						'bg-surface-2 border border-border rounded-[var(--radius-button)]',
						'font-mono text-[12px] tabular text-text',
						'hover:bg-surface-3 hover:border-border-strong transition-colors',
					)}
					aria-label="Connected wallet"
				>
					<span className="h-1.5 w-1.5 rounded-full bg-sage" />
					{truncate(account.address)}
					<ChevronDown className="h-3 w-3 text-text-3" />
				</button>
				{open && (
					<div
						className={cn(
							'absolute mt-2 w-[280px] z-50 surface-raised p-1.5 border border-border rounded-[var(--radius-card)] shadow-lg',
							anchorClass,
						)}
					>
						<div className="px-3 py-2.5 border-b border-border">
							<div className="smallcaps text-text-3">Connected</div>
							<div className="font-mono text-[12px] tabular text-text mt-1 break-all">
								{account.address}
							</div>
						</div>
						<button
							type="button"
							onClick={() => {
								void navigator.clipboard.writeText(account.address);
								setCopied(true);
								setTimeout(() => setCopied(false), 1400);
							}}
							className="w-full text-left smallcaps text-text-2 hover:text-text hover:bg-surface-3 rounded px-3 py-2 inline-flex items-center gap-2"
						>
							{copied ? <Check className="h-3 w-3 text-sage" /> : <Wallet className="h-3 w-3" />}
							{copied ? 'Copied' : 'Copy address'}
						</button>
						<button
							type="button"
							onClick={() => {
								disconnect();
								setOpen(false);
							}}
							className="w-full text-left smallcaps text-clay hover:bg-clay/10 rounded px-3 py-2 inline-flex items-center gap-2"
						>
							<X className="h-3 w-3" />
							Disconnect
						</button>
					</div>
				)}
			</div>
		);
	}

	return (
		<div className="relative inline-block w-fit" ref={popRef}>
			<Button
				size="sm"
				variant="secondary"
				onClick={() => setOpen((v) => !v)}
				disabled={wallets.length === 0 || isConnecting}
			>
				{isConnecting ? (
					<>
						<Loader2 className="h-3.5 w-3.5 animate-spin" />
						Reconnecting…
					</>
				) : (
					<>
						<Wallet className="h-3.5 w-3.5" />
						{wallets.length === 0 ? 'No wallet' : 'Connect wallet'}
					</>
				)}
			</Button>
			{open && wallets.length > 0 && (
				<div
					className={cn(
						'absolute mt-2 w-[260px] z-50 surface-raised p-1.5 border border-border rounded-[var(--radius-card)] shadow-lg max-h-[min(70vh,420px)] overflow-y-auto',
						anchorClass,
					)}
				>
					<div className="px-3 py-2 smallcaps text-text-3 border-b border-border mb-1 sticky top-0 bg-surface-2 z-10">
						Pick a wallet
					</div>
					{sortedWallets.map((w) => (
						<button
							key={w.name}
							type="button"
							onClick={() => {
								setConnectError(null);
								connectingRef.current = true;
								connect({ wallet: w })
									.then(() => {
										connectingRef.current = false;
										setOpen(false);
									})
									.catch((err: unknown) => {
										connectingRef.current = false;
										const msg = err instanceof Error ? err.message : String(err);
										// User-cancellations are not errors. Don't shout.
										if (isUserCancelled(msg)) {
											setConnectError(null);
											return;
										}
										console.error('[wallet connect failed]', err);
										setConnectError(msg);
									});
							}}
							className="w-full flex items-center gap-3 px-3 py-2.5 rounded text-left hover:bg-surface-3 transition-colors"
						>
							{w.icon && (
								/* eslint-disable-next-line @next/next/no-img-element */
								<img src={w.icon} alt="" className="h-5 w-5 rounded" />
							)}
							<span className="text-[14px] text-text">{w.name}</span>
						</button>
					))}
					{connectError && (
						<div className="px-3 py-2 mt-1 border-t border-border text-[12px] text-clay leading-[1.45]">
							{connectError}
						</div>
					)}
				</div>
			)}
		</div>
	);
}
