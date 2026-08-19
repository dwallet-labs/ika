'use client';

import { AnimatePresence, motion } from 'framer-motion';
import {
	Fingerprint,
	KeyRound,
	Laptop,
	ShieldCheck,
	Smartphone,
	Tablet,
	UsbIcon,
	Watch,
} from 'lucide-react';
import * as React from 'react';

import { cn } from '../lib/cn';

interface Device {
	id: string;
	label: string;
	icon: React.ReactNode;
}

const DEVICES: Device[] = [
	{
		id: 'phone',
		label: 'iPhone',
		icon: <Smartphone className="h-3.5 w-3.5" />,
	},
	{ id: 'laptop', label: 'MacBook', icon: <Laptop className="h-3.5 w-3.5" /> },
	{ id: 'yubi', label: 'YubiKey', icon: <UsbIcon className="h-3.5 w-3.5" /> },
	{ id: 'tablet', label: 'iPad', icon: <Tablet className="h-3.5 w-3.5" /> },
	{
		id: 'watch',
		label: 'Apple Watch',
		icon: <Watch className="h-3.5 w-3.5" />,
	},
	{
		id: 'android',
		label: 'Pixel',
		icon: <Fingerprint className="h-3.5 w-3.5" />,
	},
	{ id: 'key', label: 'Solo Key', icon: <KeyRound className="h-3.5 w-3.5" /> },
	{
		id: 'tpm',
		label: 'TPM 2.0',
		icon: <ShieldCheck className="h-3.5 w-3.5" />,
	},
];

/**
 * Interactive threshold dial. N device markers around a circle, k of them
 * "active" demonstrates the protocol. User can tap any marker to toggle
 * its state, watch the threshold meter fill, and see the vault unlock
 * when k of N is reached.
 *
 * Responsive: shrinks on narrow viewports so it fits 320px+ phones.
 */
export function VaultDial({
	initialThreshold = 3,
	count = 5,
}: {
	initialThreshold?: number;
	count?: number;
}) {
	const [threshold] = React.useState(initialThreshold);
	const [active, setActive] = React.useState<Set<string>>(new Set());
	const [radius, setRadius] = React.useState(168);

	React.useEffect(() => {
		const update = () => {
			const w = window.innerWidth;
			if (w < 380) setRadius(110);
			else if (w < 640) setRadius(130);
			else if (w < 1024) setRadius(150);
			else setRadius(168);
		};
		update();
		window.addEventListener('resize', update);
		return () => window.removeEventListener('resize', update);
	}, []);

	const RADIUS = radius;
	const SIZE = RADIUS * 2 + 56;

	React.useEffect(() => {
		const t1 = setTimeout(() => {
			setActive((s) => new Set([...s, 'phone']));
		}, 1200);
		const t2 = setTimeout(() => {
			setActive((s) => new Set([...s, 'tablet']));
		}, 2200);
		return () => {
			clearTimeout(t1);
			clearTimeout(t2);
		};
	}, []);

	const visibleDevices = DEVICES.slice(0, count);
	const approved = Array.from(active).filter((id) =>
		visibleDevices.some((d) => d.id === id),
	).length;
	const unlocked = approved >= threshold;

	function toggle(id: string) {
		setActive((prev) => {
			const next = new Set(prev);
			if (next.has(id)) next.delete(id);
			else next.add(id);
			return next;
		});
	}

	function reset() {
		setActive(new Set());
	}

	return (
		<div className="relative flex items-center justify-center">
			<AnimatePresence>
				{unlocked && (
					<motion.div
						key="halo"
						initial={{ opacity: 0, scale: 0.85 }}
						animate={{ opacity: 1, scale: 1 }}
						exit={{ opacity: 0, scale: 0.85 }}
						transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
						className="absolute pointer-events-none"
						style={{
							width: SIZE + 80,
							height: SIZE + 80,
							borderRadius: 9999,
							background: 'radial-gradient(closest-side, rgba(156,175,136,0.18), transparent 70%)',
						}}
					/>
				)}
			</AnimatePresence>

			<div className="relative" style={{ width: SIZE, height: SIZE }}>
				<svg
					width={SIZE}
					height={SIZE}
					className="absolute inset-0 pointer-events-none"
					aria-hidden
				>
					<defs>
						<radialGradient id="dialFill" cx="50%" cy="50%" r="50%">
							<stop offset="0%" stopColor="rgba(200,121,99,0.05)" />
							<stop offset="60%" stopColor="rgba(200,121,99,0.02)" />
							<stop offset="100%" stopColor="rgba(200,121,99,0)" />
						</radialGradient>
					</defs>
					<circle cx={SIZE / 2} cy={SIZE / 2} r={RADIUS + 16} fill="url(#dialFill)" />
					<circle
						cx={SIZE / 2}
						cy={SIZE / 2}
						r={RADIUS + 16}
						fill="none"
						stroke="var(--color-border)"
						strokeWidth="1"
						strokeDasharray="2 6"
					/>
					<circle
						cx={SIZE / 2}
						cy={SIZE / 2}
						r={RADIUS - 32}
						fill="none"
						stroke="var(--color-border)"
						strokeWidth="1"
					/>

					<ProgressArc
						size={SIZE}
						radius={RADIUS - 16}
						progress={Math.min(approved / threshold, 1)}
					/>

					{visibleDevices.map((d, i) => {
						const angle = (i / visibleDevices.length) * Math.PI * 2 - Math.PI / 2;
						const x = SIZE / 2 + Math.cos(angle) * RADIUS;
						const y = SIZE / 2 + Math.sin(angle) * RADIUS;
						const isActive = active.has(d.id);
						return (
							<line
								key={d.id}
								x1={SIZE / 2}
								y1={SIZE / 2}
								x2={x}
								y2={y}
								stroke={isActive ? 'var(--color-clay)' : 'var(--color-border)'}
								strokeWidth={isActive ? '1.5' : '0.6'}
								strokeOpacity={isActive ? 0.6 : 0.4}
								strokeDasharray={isActive ? '0' : '2 4'}
								className="transition-all duration-500"
							/>
						);
					})}
				</svg>

				<CenterCounter
					approved={approved}
					threshold={threshold}
					total={visibleDevices.length}
					unlocked={unlocked}
					onReset={reset}
				/>

				{visibleDevices.map((d, i) => {
					const angle = (i / visibleDevices.length) * Math.PI * 2 - Math.PI / 2;
					const x = SIZE / 2 + Math.cos(angle) * RADIUS;
					const y = SIZE / 2 + Math.sin(angle) * RADIUS;
					const isActive = active.has(d.id);
					return (
						<DeviceMarker
							key={d.id}
							x={x}
							y={y}
							label={d.label}
							icon={d.icon}
							active={isActive}
							onClick={() => toggle(d.id)}
						/>
					);
				})}
			</div>
		</div>
	);
}

function ProgressArc({
	size,
	radius,
	progress,
}: {
	size: number;
	radius: number;
	progress: number;
}) {
	const circumference = 2 * Math.PI * radius;
	const offset = circumference * (1 - progress);
	return (
		<circle
			cx={size / 2}
			cy={size / 2}
			r={radius}
			fill="none"
			stroke="var(--color-clay)"
			strokeWidth="2"
			strokeLinecap="round"
			strokeDasharray={circumference}
			strokeDashoffset={offset}
			transform={`rotate(-90 ${size / 2} ${size / 2})`}
			style={{
				transition: 'stroke-dashoffset 700ms cubic-bezier(0.22,1,0.36,1)',
			}}
		/>
	);
}

function CenterCounter({
	approved,
	threshold,
	total,
	unlocked,
	onReset,
}: {
	approved: number;
	threshold: number;
	total: number;
	unlocked: boolean;
	onReset: () => void;
}) {
	return (
		<div className="absolute inset-0 flex items-center justify-center">
			<div className="surface-raised flex flex-col items-center justify-center text-center w-[156px] h-[156px] rounded-full">
				<span className="smallcaps text-text-3 mt-1">Approvals</span>
				<div className="flex items-baseline gap-1 mt-1.5">
					<AnimatePresence mode="popLayout">
						<motion.span
							key={approved}
							initial={{ y: -20, opacity: 0 }}
							animate={{ y: 0, opacity: 1 }}
							exit={{ y: 20, opacity: 0 }}
							transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
							className="font-display text-[64px] leading-none tabular text-text"
						>
							{approved}
						</motion.span>
					</AnimatePresence>
					<span className="font-display text-[34px] leading-none text-text-3">/{threshold}</span>
				</div>
				<div className="mt-2 text-[11px] text-text-3 tabular">of {total} devices</div>
				<AnimatePresence>
					{unlocked && (
						<motion.button
							key="reset"
							initial={{ opacity: 0, y: 4 }}
							animate={{ opacity: 1, y: 0 }}
							exit={{ opacity: 0, y: 4 }}
							onClick={onReset}
							className="mt-2 smallcaps text-sage hover:text-text transition-colors"
						>
							✓ Unlocked · Reset
						</motion.button>
					)}
				</AnimatePresence>
			</div>
		</div>
	);
}

function DeviceMarker({
	x,
	y,
	label,
	icon,
	active,
	onClick,
}: {
	x: number;
	y: number;
	label: string;
	icon: React.ReactNode;
	active: boolean;
	onClick: () => void;
}) {
	return (
		<motion.button
			onClick={onClick}
			type="button"
			whileTap={{ scale: 0.9 }}
			whileHover={{ scale: 1.06 }}
			className={cn(
				'group absolute -translate-x-1/2 -translate-y-1/2',
				'flex items-center justify-center',
				'rounded-full transition-all duration-300',
				'h-11 w-11 border',
				active
					? 'bg-clay text-bg border-clay shadow-[0_0_24px_-6px_rgba(200,121,99,0.7)]'
					: 'bg-surface-2 text-text-2 border-border hover:border-clay hover:text-clay',
			)}
			style={{ left: x, top: y }}
			aria-label={`${active ? 'Disable' : 'Enable'} ${label}`}
		>
			{icon}
			<span
				className={cn(
					'absolute top-full mt-2 smallcaps whitespace-nowrap',
					active ? 'text-clay' : 'text-text-3 group-hover:text-text',
				)}
			>
				{label}
			</span>
		</motion.button>
	);
}
