'use client';

import { ArrowLeft, type LucideIcon } from 'lucide-react';
import { useRouter } from 'next/navigation';

import { cn } from '../lib/cn';
import { Card } from './ui/card';

interface SkeletonProps {
	className?: string;
}

/** Soft pulsing rectangle, sized by className. */
export function Skeleton({ className }: SkeletonProps) {
	return <div className={cn('bg-surface-3 rounded animate-pulse', className)} aria-hidden />;
}

/** A line of text-shaped placeholder. Pass `w-2/3`, `w-full`, etc. */
export function SkeletonLine({ className }: SkeletonProps) {
	return <Skeleton className={cn('h-3.5', className)} />;
}

interface ProposalDetailSkeletonProps {
	recoveryId: string;
	idStr: string;
	/** Smallcaps eyebrow above the id ("Enrollment", "Roster change"). */
	kindLabel: string;
	/** Tailwind text-* class for the eyebrow (e.g. "text-clay", "text-text-3"). */
	kindAccent?: string;
	/** Optional small icon next to the eyebrow. */
	Icon?: LucideIcon;
}

/**
 * Shared loading skeleton for proposal/enrollment/roster-change detail pages.
 * Shape mirrors the real layout so the cross-fade on data arrival doesn't
 * shift any pixels — back link, eyebrow + #id, approvals card, action row.
 */
export function ProposalDetailSkeleton({
	recoveryId,
	idStr,
	kindLabel,
	kindAccent = 'text-text-3',
	Icon,
}: ProposalDetailSkeletonProps) {
	const router = useRouter();
	return (
		<div className="max-w-[820px] mx-auto py-10">
			<button
				type="button"
				onClick={() => router.push(`/vault/${recoveryId}`)}
				className="smallcaps text-text-3 hover:text-text inline-flex items-center gap-1.5 mb-6"
			>
				<ArrowLeft className="h-3 w-3" />
				Back to vault
			</button>

			<header className="mb-6">
				<div className={cn('smallcaps inline-flex items-center gap-1.5', kindAccent)}>
					{Icon && <Icon className="h-3 w-3" />}
					{kindLabel} #{idStr}
				</div>
				<SkeletonLine className="mt-3 h-7 sm:h-9 w-2/3 max-w-[320px]" />
			</header>

			<Card tone="raised" className="p-0 overflow-hidden">
				<div className="px-5 sm:px-8 py-3 border-b border-border flex items-baseline justify-between">
					<span className="smallcaps text-text-3">Approvals</span>
					<SkeletonLine className="w-16" />
				</div>
				<div className="px-5 sm:px-8 py-6 sm:py-7 flex items-baseline gap-3">
					<Skeleton className="h-[36px] sm:h-[52px] w-12 sm:w-16" />
					<span className="font-display italic text-text-3 text-[16px] sm:text-[20px] tracking-tight">
						of
					</span>
					<Skeleton className="h-[36px] sm:h-[52px] w-12 sm:w-16" />
				</div>
				<div className="px-5 sm:px-8 pb-5">
					<Skeleton className="h-1.5 w-full" />
				</div>
				<div className="px-5 sm:px-8 py-4 border-t border-border space-y-3">
					<SkeletonLine className="w-2/3" />
					<SkeletonLine className="w-1/2" />
				</div>
			</Card>

			<Card tone="raised" className="mt-4 px-5 sm:px-8 py-5 space-y-3">
				<SkeletonLine className="w-1/3" />
				<Skeleton className="h-12 w-full" />
			</Card>
		</div>
	);
}

/** A single proposal-card sized placeholder. Mirrors `ProposalCard`'s shape. */
export function ProposalCardSkeleton() {
	return (
		<div className="surface-raised border border-border rounded-[var(--radius-card)] p-5">
			<div className="flex items-baseline justify-between gap-2 mb-3">
				<SkeletonLine className="h-6 w-12" />
				<SkeletonLine className="w-16" />
			</div>
			<div className="flex items-baseline gap-2 mb-3">
				<Skeleton className="h-9 w-10" />
				<span className="font-display italic text-text-3 text-[16px] tracking-tight">of</span>
				<Skeleton className="h-9 w-10" />
				<SkeletonLine className="ml-auto w-10" />
			</div>
			<Skeleton className="h-1 w-full mb-3" />
			<div className="flex items-center justify-between gap-2">
				<SkeletonLine className="w-2/5" />
				<SkeletonLine className="w-12" />
			</div>
		</div>
	);
}
