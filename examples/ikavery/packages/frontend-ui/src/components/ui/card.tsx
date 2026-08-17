import * as React from 'react';

import { cn } from '../../lib/cn';

const Card = React.forwardRef<
	HTMLDivElement,
	React.HTMLAttributes<HTMLDivElement> & {
		tone?: 'vault' | 'raised' | 'outline';
	}
>(({ className, tone = 'vault', ...props }, ref) => (
	<div
		ref={ref}
		className={cn(
			'relative overflow-hidden rounded-[var(--radius-card)]',
			tone === 'vault' && 'bg-surface border border-border',
			tone === 'raised' &&
				'bg-surface-2 border border-border shadow-[0_1px_0_0_rgba(255,255,255,0.04)_inset,0_16px_32px_-16px_rgba(0,0,0,0.6)]',
			tone === 'outline' && 'bg-transparent border border-border-strong',
			className,
		)}
		{...props}
	/>
));
Card.displayName = 'Card';

const CardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
	({ className, ...props }, ref) => (
		<div
			ref={ref}
			className={cn('flex items-center justify-between px-5 pt-5 pb-3', className)}
			{...props}
		/>
	),
);
CardHeader.displayName = 'CardHeader';

const CardTitle = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
	({ className, ...props }, ref) => (
		<div
			ref={ref}
			className={cn('font-pixel text-[10px] tracking-[0.08em] uppercase text-text-2', className)}
			{...props}
		/>
	),
);
CardTitle.displayName = 'CardTitle';

const CardEyebrow = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
	({ className, ...props }, ref) => (
		<div
			ref={ref}
			className={cn('font-pixel text-[10px] tracking-[0.08em] uppercase text-text-3', className)}
			{...props}
		/>
	),
);
CardEyebrow.displayName = 'CardEyebrow';

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
	({ className, ...props }, ref) => (
		<div ref={ref} className={cn('px-5 pb-5', className)} {...props} />
	),
);
CardContent.displayName = 'CardContent';

const CardFooter = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
	({ className, ...props }, ref) => (
		<div
			ref={ref}
			className={cn(
				'flex items-center justify-between px-5 py-3 border-t border-border bg-surface-2/50',
				className,
			)}
			{...props}
		/>
	),
);
CardFooter.displayName = 'CardFooter';

export { Card, CardContent, CardEyebrow, CardFooter, CardHeader, CardTitle };
