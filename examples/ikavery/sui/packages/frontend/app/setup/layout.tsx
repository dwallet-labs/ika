'use client';

import { cn, Shell } from '@fesal-packages/ikavery-frontend-ui';
import { AnimatePresence, motion } from 'framer-motion';
import { ArrowLeft } from 'lucide-react';
import { usePathname } from 'next/navigation';
import type * as React from 'react';

import { AppDisclaimerModal } from '@/components/app-disclaimer-modal';
import { AppShellHeader } from '@/components/app-shell-header';

const STEPS = [
	{ slug: 'connect', label: 'Device' },
	{ slug: 'threshold', label: 'Quorum' },
	{ slug: 'key', label: 'Key' },
	{ slug: 'review', label: 'Review' },
	{ slug: 'sealed', label: 'Sealed' },
];

export default function SetupLayout({ children }: { children: React.ReactNode }) {
	const pathname = usePathname();
	const currentSlug = pathname.split('/').pop() ?? 'connect';
	const currentIndex = Math.max(
		0,
		STEPS.findIndex((s) => s.slug === currentSlug),
	);

	return (
		<Shell>
			<AppDisclaimerModal />
			<AppShellHeader />

			<Stepper currentIndex={currentIndex} />

			<main className="mx-auto max-w-[1280px] px-4 sm:px-6 lg:px-10 py-10 sm:py-14 lg:py-20">
				<AnimatePresence mode="wait">
					<motion.div
						key={pathname}
						initial={{ opacity: 0, y: 16, filter: 'blur(8px)' }}
						animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
						exit={{ opacity: 0, y: -8, filter: 'blur(8px)' }}
						transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
					>
						{children}
					</motion.div>
				</AnimatePresence>
			</main>
		</Shell>
	);
}

function Stepper({ currentIndex }: { currentIndex: number }) {
	return (
		<div className="hairline-b">
			<div className="mx-auto max-w-[1280px] px-4 sm:px-6 lg:px-10 py-3 sm:py-4 flex items-center gap-3 sm:gap-5">
				<a
					href="/"
					className="flex-none flex items-center gap-1.5 smallcaps text-text-3 hover:text-text transition-colors"
				>
					<ArrowLeft className="h-3 w-3" />
					<span className="hidden sm:inline">Home</span>
				</a>
				<span className="rule-h flex-none w-6 hidden sm:block" />
				<ol className="flex items-center gap-2 sm:gap-5 flex-1 min-w-0">
					{STEPS.map((s, i) => {
						const done = i < currentIndex;
						const active = i === currentIndex;
						return (
							<li key={s.slug} className="flex items-center gap-2 sm:gap-5 flex-none">
								<div className="flex items-center gap-2 sm:gap-2.5 flex-none">
									<span
										className={cn(
											'h-5 w-5 rounded-full inline-flex items-center justify-center font-mono text-[10px] tabular border transition-colors',
											active
												? 'bg-clay text-bg border-clay'
												: done
													? 'bg-sage/15 text-sage border-sage/40'
													: 'bg-surface-2 text-text-3 border-border',
										)}
									>
										{done ? '✓' : String(i + 1).padStart(2, '0')}
									</span>
									<span
										className={cn(
											'smallcaps whitespace-nowrap',
											// Only the active label shows on phones — others collapse
											// to just the circle so the whole stepper fits 375px.
											!active && 'hidden sm:inline',
											active ? 'text-text' : done ? 'text-text-2' : 'text-text-3',
										)}
									>
										{s.label}
									</span>
								</div>
								{i < STEPS.length - 1 && (
									<span
										className={cn(
											'h-px flex-1 sm:flex-none w-3 sm:w-10 min-w-[12px]',
											done ? 'bg-sage/40' : 'bg-border',
										)}
									/>
								)}
							</li>
						);
					})}
				</ol>
			</div>
		</div>
	);
}
