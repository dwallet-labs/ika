'use client';

import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import * as React from 'react';

import { cn } from '../../lib/cn';

const buttonVariants = cva(
	[
		'relative inline-flex items-center justify-center gap-2 whitespace-nowrap',
		'font-medium text-[13px] tracking-[-0.005em]',
		'transition-[transform,background,color,border-color,box-shadow] duration-200 ease-out',
		'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-clay/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
		'disabled:pointer-events-none disabled:opacity-40',
		'select-none',
		'rounded-[var(--radius-button)]',
		'active:translate-y-[0.5px]',
	].join(' '),
	{
		variants: {
			variant: {
				default: [
					'bg-text text-bg hover:bg-text/95',
					'shadow-[0_1px_0_0_rgba(255,255,255,0.18)_inset,0_2px_4px_0_rgba(0,0,0,0.4)]',
				].join(' '),
				primary: [
					'bg-clay text-bg hover:bg-clay-bright',
					'shadow-[0_1px_0_0_rgba(255,255,255,0.22)_inset,0_8px_24px_-8px_rgba(200,121,99,0.55),0_0_0_1px_rgba(200,121,99,0.45)]',
					'hover:shadow-[0_1px_0_0_rgba(255,255,255,0.28)_inset,0_12px_32px_-8px_rgba(200,121,99,0.65),0_0_0_1px_rgba(220,143,122,0.55)]',
				].join(' '),
				secondary:
					'bg-surface-2 text-text border border-border hover:bg-surface-3 hover:border-border-strong',
				ghost: 'bg-transparent text-text-2 hover:text-text hover:bg-surface-2',
				outline:
					'bg-transparent text-text border border-border-strong hover:border-clay hover:text-clay',
				irreversible: [
					'bg-transparent text-clay border border-clay/50',
					'hover:bg-clay-glow hover:border-clay',
					'shadow-[0_0_24px_-12px_rgba(200,121,99,0.5)]',
				].join(' '),
				link: 'bg-transparent text-clay hover:text-clay-bright border-0 px-0 h-auto',
			},
			size: {
				default: 'h-10 px-4',
				sm: 'h-8 px-3 text-[12px]',
				lg: 'h-12 px-6 text-[14px]',
				xl: 'h-14 px-8 text-[15px]',
				icon: 'h-10 w-10',
			},
		},
		defaultVariants: {
			variant: 'default',
			size: 'default',
		},
	},
);

export interface ButtonProps
	extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
	asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
	({ className, variant, size, asChild = false, ...props }, ref) => {
		const Comp = asChild ? Slot : 'button';
		return (
			<Comp className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props} />
		);
	},
);
Button.displayName = 'Button';

export { Button, buttonVariants };
