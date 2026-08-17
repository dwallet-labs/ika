'use client';

import { useDynamicContext } from '@dynamic-labs/sdk-react-core';
import { Button, cn, truncateAddress } from '@fesal-packages/ikavery-frontend-ui';
import { Check, ChevronDown, Loader2, Wallet, X } from 'lucide-react';
import * as React from 'react';

/**
 * Visual parity with Sui's `wallet-connect-impl`. Disconnected state shows a
 * design-system Button that opens Dynamic's auth flow; connected state shows
 * an address pill with a copy/disconnect popover. Avoids `<DynamicWidget />`
 * because its native pill does not match the editorial palette.
 */
export default function WalletConnectImpl({
	align = 'end',
}: {
	align?: 'start' | 'end';
} = {}) {
	const { primaryWallet, setShowAuthFlow, handleLogOut, sdkHasLoaded } = useDynamicContext();
	const [open, setOpen] = React.useState(false);
	const [copied, setCopied] = React.useState(false);
	const popRef = React.useRef<HTMLDivElement>(null);
	const anchorClass = align === 'end' ? 'right-0' : 'left-0';

	React.useEffect(() => {
		function onDoc(e: MouseEvent) {
			if (popRef.current && !popRef.current.contains(e.target as Node)) {
				setOpen(false);
			}
		}
		if (open) document.addEventListener('mousedown', onDoc);
		return () => document.removeEventListener('mousedown', onDoc);
	}, [open]);

	if (!sdkHasLoaded) {
		return (
			<Button size="sm" variant="secondary" disabled>
				<Loader2 className="h-3.5 w-3.5 animate-spin" />
				Loading
			</Button>
		);
	}

	if (primaryWallet) {
		const address = primaryWallet.address;
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
					{truncateAddress(address, 6, 4)}
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
								{address}
							</div>
						</div>
						<button
							type="button"
							onClick={() => {
								void navigator.clipboard.writeText(address);
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
								void handleLogOut();
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
		<Button size="sm" variant="secondary" onClick={() => setShowAuthFlow(true)}>
			<Wallet className="h-3.5 w-3.5" />
			Connect wallet
		</Button>
	);
}
