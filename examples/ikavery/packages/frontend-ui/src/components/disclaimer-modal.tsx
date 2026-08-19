'use client';

import { AnimatePresence, motion } from 'framer-motion';
import { ShieldAlert } from 'lucide-react';
import * as React from 'react';

import { Button } from './ui/button';

export interface DisclaimerClause {
	/** Two-digit ordinal shown in the marginalia, e.g. "01". */
	ord: string;
	text: React.ReactNode;
}

export interface DisclaimerModalProps {
	/**
	 * Per-app localStorage key. The modal hides itself once "accepted" is
	 * recorded under this key, so each chain-flavour can have its own gate.
	 */
	storageKey: string;
	/** Eyebrow above the title. Defaults to "Proof of concept · Demo only". */
	eyebrow?: string;
	/** Display heading. Pass markup if you want the italic break. */
	title?: React.ReactNode;
	/** Lead paragraph under the title. */
	intro?: React.ReactNode;
	/** Numbered clauses. Each clause needs an `ord` and rich-text body. */
	clauses: DisclaimerClause[];
	/** Checkbox label copy. */
	checkboxLabel?: React.ReactNode;
	/** CTA button label. */
	acceptLabel?: string;
}

const DEFAULT_TITLE = (
	<>
		Read this before
		<br />
		<span className="italic text-text-2">continuing.</span>
	</>
);

const DEFAULT_CHECKBOX = (
	<>
		I understand this is a proof of concept, not for real funds or production use, and I accept the
		terms above.
	</>
);

export function DisclaimerModal({
	storageKey,
	eyebrow = 'Proof of concept · Demo only',
	title = DEFAULT_TITLE,
	intro,
	clauses,
	checkboxLabel = DEFAULT_CHECKBOX,
	acceptLabel = 'I understand, continue',
}: DisclaimerModalProps) {
	const [open, setOpen] = React.useState(false);
	const [accepted, setAccepted] = React.useState(false);
	const [mounted, setMounted] = React.useState(false);

	React.useEffect(() => {
		setMounted(true);
		if (typeof window === 'undefined') return;
		try {
			const saved = window.localStorage.getItem(storageKey);
			if (saved !== 'accepted') setOpen(true);
		} catch {
			setOpen(true);
		}
	}, [storageKey]);

	React.useEffect(() => {
		if (!open) return;
		const prev = document.body.style.overflow;
		document.body.style.overflow = 'hidden';
		return () => {
			document.body.style.overflow = prev;
		};
	}, [open]);

	function accept() {
		try {
			window.localStorage.setItem(storageKey, 'accepted');
		} catch {
			/* private mode, etc; modal won't re-show this session */
		}
		setOpen(false);
	}

	if (!mounted) return null;

	return (
		<AnimatePresence>
			{open && (
				<motion.div
					key="overlay"
					className="fixed inset-0 z-[100] flex items-center justify-center px-4 py-6"
					initial={{ opacity: 0 }}
					animate={{ opacity: 1 }}
					exit={{ opacity: 0 }}
					transition={{ duration: 0.4 }}
					aria-modal="true"
					role="dialog"
					aria-labelledby="disclaimer-title"
				>
					<div
						className="absolute inset-0 backdrop-blur-md"
						style={{ background: 'rgba(15, 17, 20, 0.78)' }}
						aria-hidden
					/>

					<motion.div
						initial={{ opacity: 0, y: 20, scale: 0.98 }}
						animate={{ opacity: 1, y: 0, scale: 1 }}
						exit={{ opacity: 0, y: 12, scale: 0.98 }}
						transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
						className="relative surface-raised w-full max-w-[640px] max-h-[88vh] overflow-y-auto"
					>
						<div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-clay to-transparent" />

						<div className="px-5 sm:px-7 lg:px-9 pt-6 sm:pt-7 lg:pt-9 pb-3">
							<div className="flex items-start gap-3 mb-5">
								<span className="h-9 w-9 flex-none flex items-center justify-center rounded-md border border-clay/40 bg-clay/10">
									<ShieldAlert className="h-4 w-4 text-clay" strokeWidth={1.7} />
								</span>
								<div>
									<div className="smallcaps text-clay">{eyebrow}</div>
									<h2
										id="disclaimer-title"
										className="font-display text-[26px] sm:text-[34px] lg:text-[40px] leading-[1.04] tracking-[-0.02em] text-text mt-1"
									>
										{title}
									</h2>
								</div>
							</div>

							{intro && (
								<p className="text-[14px] leading-[1.6] text-text-2 max-w-[540px]">{intro}</p>
							)}
						</div>

						<div className="px-5 sm:px-7 lg:px-9 pb-5 pt-4 space-y-2">
							{clauses.map((c) => (
								<div
									key={c.ord}
									className="flex gap-4 py-2.5 border-b border-border last:border-b-0 text-[13px] leading-[1.6] text-text-2"
								>
									<span className="font-mono text-[11px] text-text-4 tabular flex-none mt-0.5">
										{c.ord}
									</span>
									<span>{c.text}</span>
								</div>
							))}
						</div>

						<div className="px-5 sm:px-7 lg:px-9 pt-3 pb-6 sm:pb-7 lg:pb-9 sticky bottom-0 bg-surface-2 border-t border-border mt-2">
							<label className="flex items-start gap-3 cursor-pointer group select-none">
								<input
									type="checkbox"
									checked={accepted}
									onChange={(e) => setAccepted(e.target.checked)}
									className="sr-only peer"
								/>
								<span
									className={`mt-0.5 h-4 w-4 flex-none rounded-[3px] border transition-colors ${
										accepted
											? 'bg-clay border-clay'
											: 'bg-transparent border-border-strong group-hover:border-text-2'
									} peer-focus-visible:ring-2 peer-focus-visible:ring-clay/60 peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-surface-2`}
									aria-hidden
								>
									{accepted && (
										<svg viewBox="0 0 16 16" className="h-full w-full">
											<path
												d="M3 8l3 3 7-7"
												fill="none"
												stroke="var(--color-canvas)"
												strokeWidth="2.4"
												strokeLinecap="square"
											/>
										</svg>
									)}
								</span>
								<span className="text-[13.5px] text-text-2 leading-[1.55]">{checkboxLabel}</span>
							</label>

							<div className="mt-5 flex justify-end">
								<Button variant="primary" size="default" disabled={!accepted} onClick={accept}>
									{acceptLabel}
								</Button>
							</div>
						</div>
					</motion.div>
				</motion.div>
			)}
		</AnimatePresence>
	);
}
