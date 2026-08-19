'use client';

import { motion } from 'framer-motion';
import * as React from 'react';

import { cn } from '../lib/cn';

interface TileProps extends React.HTMLAttributes<HTMLDivElement> {
	span?: { col?: number; row?: number };
	tone?: 'default' | 'raised' | 'outline';
	interactive?: boolean;
}

export const Tile = React.forwardRef<HTMLDivElement, TileProps>(
	({ className, span, tone = 'default', interactive = false, ...props }, ref) => {
		const colSpan =
			span?.col === 2
				? 'sm:col-span-2 lg:col-span-2'
				: span?.col === 3
					? 'sm:col-span-2 lg:col-span-3'
					: 'lg:col-span-1';
		const rowSpan =
			span?.row === 2 ? 'lg:row-span-2' : span?.row === 3 ? 'lg:row-span-3' : 'lg:row-span-1';

		const Component: React.ElementType = interactive ? motion.div : 'div';
		const motionProps = interactive
			? {
					whileHover: { y: -2 },
					transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] },
				}
			: {};

		return (
			<Component
				ref={ref}
				className={cn(
					'relative overflow-hidden rounded-[var(--radius-card)]',
					'p-5 sm:p-6',
					tone === 'default' && 'bg-surface border border-border',
					tone === 'raised' &&
						'bg-surface-2 border border-border shadow-[0_1px_0_0_rgba(255,255,255,0.04)_inset,0_30px_60px_-30px_rgba(0,0,0,0.65)]',
					tone === 'outline' && 'bg-transparent border border-border-strong',
					interactive && 'transition-colors hover:border-border-strong',
					colSpan,
					rowSpan,
					className,
				)}
				{...motionProps}
				{...(props as React.HTMLAttributes<HTMLDivElement>)}
			/>
		);
	},
);
Tile.displayName = 'Tile';

export function TileEyebrow({
	children,
	className,
}: {
	children: React.ReactNode;
	className?: string;
}) {
	return <div className={cn('smallcaps text-text-3', className)}>{children}</div>;
}

export function TileTitle({
	children,
	className,
}: {
	children: React.ReactNode;
	className?: string;
}) {
	return (
		<div
			className={cn('font-display text-[28px] leading-[1] tracking-[-0.02em] text-text', className)}
		>
			{children}
		</div>
	);
}
