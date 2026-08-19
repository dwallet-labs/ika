'use client';

import {
	motion,
	useMotionValue,
	useReducedMotion,
	useSpring,
	type HTMLMotionProps,
} from 'framer-motion';
import * as React from 'react';

import { cn } from '../lib/cn';

interface RevealProps extends HTMLMotionProps<'div'> {
	delay?: number;
	y?: number;
	className?: string;
}

export function Reveal({ children, delay = 0, y = 14, className, ...rest }: RevealProps) {
	const reduced = useReducedMotion();
	return (
		<motion.div
			initial={reduced ? false : { opacity: 0, y, filter: 'blur(6px)' }}
			animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
			transition={{ duration: 0.7, delay, ease: [0.22, 1, 0.36, 1] }}
			className={className}
			{...rest}
		>
			{children}
		</motion.div>
	);
}

export function TypeIn({
	text,
	delay = 0,
	stagger = 0.025,
	className,
	italic,
}: {
	text: string;
	delay?: number;
	stagger?: number;
	className?: string;
	italic?: boolean;
}) {
	const reduced = useReducedMotion();
	const characters = React.useMemo(() => Array.from(text), [text]);

	if (reduced) {
		return <span className={cn(italic && 'italic', className)}>{text}</span>;
	}

	return (
		<span className={cn('inline-block', italic && 'italic', className)} aria-label={text}>
			{characters.map((char, i) => (
				<motion.span
					key={`${char}-${i}`}
					initial={{ opacity: 0, y: 14, rotate: -3 }}
					animate={{ opacity: 1, y: 0, rotate: 0 }}
					transition={{
						duration: 0.55,
						delay: delay + i * stagger,
						ease: [0.22, 1, 0.36, 1],
					}}
					className="inline-block whitespace-pre"
					aria-hidden
				>
					{char}
				</motion.span>
			))}
		</span>
	);
}

export function CursorSpotlight() {
	const reduced = useReducedMotion();
	const [enabled, setEnabled] = React.useState(false);
	const x = useMotionValue(0);
	const y = useMotionValue(0);
	const xs = useSpring(x, { stiffness: 60, damping: 18, mass: 0.6 });
	const ys = useSpring(y, { stiffness: 60, damping: 18, mass: 0.6 });

	React.useEffect(() => {
		if (reduced) return;
		const fine = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
		if (!fine) return;
		setEnabled(true);
		x.set(window.innerWidth / 2);
		y.set(window.innerHeight / 3);
		const handler = (e: MouseEvent) => {
			x.set(e.clientX);
			y.set(e.clientY);
		};
		window.addEventListener('pointermove', handler, { passive: true });
		return () => window.removeEventListener('pointermove', handler);
	}, [reduced, x, y]);

	if (reduced || !enabled) return null;

	return <motion.div className="spotlight" style={{ left: xs, top: ys }} />;
}

export function StaggerOnView({
	children,
	className,
	stagger = 0.08,
	delay = 0,
}: {
	children: React.ReactNode[];
	className?: string;
	stagger?: number;
	delay?: number;
}) {
	const reduced = useReducedMotion();
	return (
		<motion.div
			className={className}
			initial="hidden"
			whileInView="visible"
			viewport={{ once: true, amount: 0.2 }}
			variants={{
				hidden: {},
				visible: {
					transition: { staggerChildren: stagger, delayChildren: delay },
				},
			}}
		>
			{children.map((child, i) => (
				<motion.div
					key={i}
					variants={{
						hidden: reduced ? { opacity: 1 } : { opacity: 0, y: 18, filter: 'blur(6px)' },
						visible: {
							opacity: 1,
							y: 0,
							filter: 'blur(0px)',
							transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] },
						},
					}}
				>
					{child}
				</motion.div>
			))}
		</motion.div>
	);
}

export function CountUp({
	value,
	duration = 1.2,
	prefix = '',
	suffix = '',
	pad,
}: {
	value: number;
	duration?: number;
	prefix?: string;
	suffix?: string;
	pad?: number;
}) {
	const ref = React.useRef<HTMLSpanElement>(null);
	const [shown, setShown] = React.useState(0);
	const reduced = useReducedMotion();

	React.useEffect(() => {
		if (!ref.current) return;
		if (reduced) {
			setShown(value);
			return;
		}
		const obs = new IntersectionObserver(
			([entry]) => {
				if (entry?.isIntersecting) {
					const start = performance.now();
					const tick = (now: number) => {
						const t = Math.min(1, (now - start) / (duration * 1000));
						const eased = 1 - (1 - t) ** 3;
						setShown(Math.round(value * eased));
						if (t < 1) requestAnimationFrame(tick);
					};
					requestAnimationFrame(tick);
					obs.disconnect();
				}
			},
			{ threshold: 0.3 },
		);
		obs.observe(ref.current);
		return () => obs.disconnect();
	}, [value, duration, reduced]);

	const text = pad ? shown.toString().padStart(pad, '0') : shown.toLocaleString();
	return (
		<span ref={ref} className="tabular">
			{prefix}
			{text}
			{suffix}
		</span>
	);
}
