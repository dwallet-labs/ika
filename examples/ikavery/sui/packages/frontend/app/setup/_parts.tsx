'use client';

import { cn } from '@fesal-packages/ikavery-frontend-ui';
import type * as React from 'react';

export function StepHeader({
	ord,
	title,
	italic,
	hint,
}: {
	ord: string;
	title: string;
	italic?: string;
	hint?: string;
}) {
	return (
		<header className="mb-8 sm:mb-10">
			<span className="smallcaps text-clay">{ord}</span>
			<h1 className="mt-3 font-display text-[40px] sm:text-[56px] lg:text-[72px] leading-[0.98] tracking-[-0.025em] text-text">
				{title}
				{italic && (
					<>
						<br />
						<span className="italic text-text-2">{italic}</span>
					</>
				)}
			</h1>
			{hint && (
				<p className="mt-5 max-w-[560px] text-[15px] sm:text-[16px] leading-[1.6] text-text-2">
					{hint}
				</p>
			)}
		</header>
	);
}

export function StepFooter({
	back,
	next,
	hint,
}: {
	back?: React.ReactNode;
	next?: React.ReactNode;
	hint?: React.ReactNode;
}) {
	return (
		<footer className="mt-10 sm:mt-14 pt-6 border-t border-border flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
			<div className="flex-none flex items-center gap-3">{back}</div>
			<div
				className={cn(
					'text-[12.5px] text-text-3 leading-[1.5] order-3 sm:order-2 text-center sm:text-left flex-1 px-2',
				)}
			>
				{hint}
			</div>
			<div className="flex-none flex flex-col sm:flex-row items-stretch sm:items-center gap-3 order-2 sm:order-3">
				{next}
			</div>
		</footer>
	);
}

export function FieldLabel({
	children,
	required,
	hint,
}: {
	children: React.ReactNode;
	required?: boolean;
	hint?: string;
}) {
	return (
		<div className="flex items-baseline justify-between mb-2">
			<span className="smallcaps text-text-2">
				{children}
				{required && <span className="text-clay ml-1">*</span>}
			</span>
			{hint && <span className="font-mono text-[10px] tracking-[0.04em] text-text-4">{hint}</span>}
		</div>
	);
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
	return (
		<span className={cn('font-mono text-[13px] tabular text-text break-all', className)}>
			{children}
		</span>
	);
}
