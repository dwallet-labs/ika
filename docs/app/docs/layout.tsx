import { Banner } from 'fumadocs-ui/components/banner';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { ArrowRight, BookOpen, Bot, Code2, Library, Server, Zap } from 'lucide-react';
import Image from 'next/image';
import type { ReactNode } from 'react';

import { source } from '@/lib/source';

import { baseOptions } from '../layout.config';

type TabConfig = {
	icon: ReactNode;
	description: string;
	color: string;
	bgColor: string;
};

const tabConfig: Record<string, TabConfig> = {
	'solana-integration': {
		icon: (
			<Image
				src="/solana-logo.svg"
				alt="Solana"
				width={16}
				height={16}
				className="dark:brightness-0 dark:invert"
			/>
		),
		description: 'Use Solana as the coordination chain (pre-alpha)',
		color: 'text-[#9945FF] dark:text-[#14F195]',
		bgColor: 'bg-[#9945FF]/10 dark:bg-[#14F195]/10',
	},
	'get-started': {
		icon: <Zap className="size-4" />,
		description: 'Sign your first Bitcoin tx in under ten minutes',
		color: 'text-pink-500 dark:text-pink-400',
		bgColor: 'bg-pink-500/10 dark:bg-pink-500/20',
	},
	learn: {
		icon: <BookOpen className="size-4" />,
		description: 'Concepts, trust model, and 2PC-MPC',
		color: 'text-blue-500 dark:text-blue-400',
		bgColor: 'bg-blue-500/10 dark:bg-blue-500/20',
	},
	build: {
		icon: <Code2 className="size-4" />,
		description: 'SDK, plugins, Move integration, recipes',
		color: 'text-violet-500 dark:text-violet-400',
		bgColor: 'bg-violet-500/10 dark:bg-violet-500/20',
	},
	operate: {
		icon: <Server className="size-4" />,
		description: 'CLI, validator setup and operations, networks',
		color: 'text-emerald-500 dark:text-emerald-400',
		bgColor: 'bg-emerald-500/10 dark:bg-emerald-500/20',
	},
	reference: {
		icon: <Library className="size-4" />,
		description: 'Lookup tables: curves, events, configs, modules',
		color: 'text-amber-500 dark:text-amber-400',
		bgColor: 'bg-amber-500/10 dark:bg-amber-500/20',
	},
	'ai-skills': {
		icon: <Bot className="size-4" />,
		description: 'Skills that load Ika context into AI coding agents',
		color: 'text-fuchsia-500 dark:text-fuchsia-400',
		bgColor: 'bg-fuchsia-500/10 dark:bg-fuchsia-500/20',
	},
};

function TabIcon({ config }: { config: TabConfig }) {
	return (
		<div
			className={`
      relative flex items-center justify-center size-8 rounded-lg
      ${config.bgColor} ${config.color}
      transition-all duration-200
    `}
		>
			{config.icon}
		</div>
	);
}

export default function Layout({ children }: { children: ReactNode }) {
	return (
		<>
			<Banner
				id="solana-banner"
				className="bg-gradient-to-r from-purple-600 via-fuchsia-500 to-pink-500 text-white"
			>
				<a
					href="https://solana-pre-alpha.ika.xyz"
					target="_blank"
					rel="noopener noreferrer"
					className="flex items-center justify-center gap-3 text-sm font-medium text-white no-underline hover:opacity-90 transition-opacity"
				>
					<Image
						src="/solana-logo.svg"
						alt="Solana"
						width={16}
						height={16}
						className="brightness-0 invert"
					/>
					<span>
						Solana coordination chain pre-alpha is live on devnet. dWallets sign for Solana natively.
					</span>
					<ArrowRight className="h-4 w-4" />
				</a>
			</Banner>
			<DocsLayout
				tree={source.pageTree}
				{...baseOptions}
				sidebar={{
					tabs: {
						transform(option, node) {
							const key = option.url.split('/')[2] ?? '';
							const config = tabConfig[key];

							if (config) {
								return {
									...option,
									icon: <TabIcon config={config} />,
									description: config.description,
								};
							}
							return option;
						},
					},
				}}
			>
				{children}
			</DocsLayout>
		</>
	);
}
