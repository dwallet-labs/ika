import type * as React from 'react';

import { cn } from '../lib/cn';

export function Shell({ children, className }: { children: React.ReactNode; className?: string }) {
	return <div className={cn('relative z-10 min-h-screen', className)}>{children}</div>;
}

export interface ShellHeaderProps {
	/** Brand label next to the logo. Defaults to "Ikavery". */
	brand?: string;
	/** Version tag shown beside brand on ≥sm. Defaults to "v0.1". */
	version?: string;
	/** Wallet connect / chain-specific button. Rendered before the CTA. */
	walletSlot?: React.ReactNode;
	/** Right-side CTA (anchor or button). */
	ctaSlot?: React.ReactNode;
	/** Anchor links rendered on ≥md viewports. Defaults to standard set. */
	navLinks?: { href: string; label: string }[];
}

const DEFAULT_NAV: ShellHeaderProps['navLinks'] = [];

export function ShellHeader({
	brand = 'Ikavery',
	version = 'v0.1',
	walletSlot,
	ctaSlot,
	navLinks = DEFAULT_NAV,
}: ShellHeaderProps) {
	return (
		<header className="sticky top-0 z-30 backdrop-blur-md bg-canvas/75 hairline-b">
			<div className="mx-auto max-w-[1280px] px-4 sm:px-6 lg:px-10 flex items-center justify-between h-14">
				<a href="/" className="flex items-center gap-2.5 sm:gap-3 group">
					<Mark />
					<span className="font-display text-[18px] tracking-[-0.015em] text-text">{brand}</span>
					{version && (
						<span className="hidden sm:inline smallcaps text-text-3 mt-[3px]">{version}</span>
					)}
				</a>

				{navLinks && navLinks.length > 0 && (
					<nav className="hidden md:flex items-center gap-8 text-[13px] text-text-2">
						{navLinks.map((l) => (
							<a key={l.href} href={l.href} className="hover:text-text transition-colors">
								{l.label}
							</a>
						))}
					</nav>
				)}

				<div className="flex items-center gap-2 sm:gap-2.5">
					{walletSlot}
					{ctaSlot}
				</div>
			</div>
		</header>
	);
}

export interface ShellFooterProps {
	/** Smallcaps tag on the left. Defaults to "Sui · Ika · Solana". */
	tag?: string;
	/** Centered "made by" line. Pass a node to override. */
	attribution?: React.ReactNode;
	/** Smallcaps tag on the right. Defaults to "© 2026 · open". */
	copyright?: string;
}

const DEFAULT_ATTRIBUTION = (
	<>
		made by{' '}
		<a
			href="https://github.com/Iamknownasfesal/ikavery"
			className="not-italic font-display text-text hover:text-clay transition-colors"
		>
			fesal
		</a>{' '}
		with <span className="not-italic">❤️</span>
	</>
);

export function ShellFooter({
	tag = 'Sui · Ika · Solana',
	attribution = DEFAULT_ATTRIBUTION,
	copyright = '© 2026 · open',
}: ShellFooterProps = {}) {
	return (
		<footer className="hairline-t mt-32">
			<div className="mx-auto max-w-[1280px] px-6 lg:px-10 py-10 sm:py-12 flex flex-col sm:flex-row items-start sm:items-baseline gap-4 sm:gap-6 justify-between">
				<span className="smallcaps text-text-3">{tag}</span>
				<span className="font-display italic text-[16px] sm:text-[18px] text-text-2 text-center order-3 sm:order-2 w-full sm:w-auto sm:flex-1">
					{attribution}
				</span>
				<span className="smallcaps text-text-3 order-2 sm:order-3">{copyright}</span>
			</div>
		</footer>
	);
}

function Mark() {
	// Pixel-art squid holding a skeleton key. 16x10 grid, 2px per cell.
	// "1" = ink (squid + tentacle/shaft); "2" = clay (key bow + tooth).
	const grid = [
		'0000011110000000',
		'0000111111000000',
		'0001111111110000',
		'0001101101100000',
		'0001111111100222',
		'0001111111111202',
		'0001111111120222',
		'0000111111000000',
		'0001010101000000',
		'0010101010100000',
	];

	return (
		<div className="relative flex h-8 w-8 items-center justify-center bg-clay/10 border border-clay/40 rounded-[3px] transition-colors group-hover:bg-clay/20 group-hover:border-clay/60">
			<svg width="32" height="20" viewBox="0 0 16 10" shapeRendering="crispEdges" aria-hidden>
				{grid.map((row, y) =>
					row
						.split('')
						.map((cell, x) =>
							cell !== '0' ? (
								<rect
									key={`${x},${y}`}
									x={x}
									y={y}
									width="1"
									height="1"
									fill={cell === '2' ? 'var(--color-clay)' : 'var(--color-text)'}
								/>
							) : null,
						),
				)}
			</svg>
		</div>
	);
}
