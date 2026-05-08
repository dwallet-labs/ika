import { Banner } from 'fumadocs-ui/components/banner';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { ArrowRight, Blocks, BookOpen, Bot, Code2, Globe, Terminal } from 'lucide-react';
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
		icon: <Globe className="size-4" />,
		description: 'Solana dWallet integration (Pre-Alpha)',
		color: 'text-purple-500 dark:text-purple-400',
		bgColor: 'bg-purple-500/10 dark:bg-purple-500/20',
	},
	sdk: {
		icon: <Code2 className="size-4" />,
		description: 'TypeScript SDK for building with Ika',
		color: 'text-pink-500 dark:text-pink-400',
		bgColor: 'bg-pink-500/10 dark:bg-pink-500/20',
	},
	cli: {
		icon: <Terminal className="size-4" />,
		description: 'dWallet operations from the terminal',
		color: 'text-emerald-500 dark:text-emerald-400',
		bgColor: 'bg-emerald-500/10 dark:bg-emerald-500/20',
	},
	'move-integration': {
		icon: <Blocks className="size-4" />,
		description: 'Integrate dWallets in Move contracts',
		color: 'text-fuchsia-500 dark:text-fuchsia-400',
		bgColor: 'bg-fuchsia-500/10 dark:bg-fuchsia-500/20',
	},
	'core-concepts': {
		icon: <BookOpen className="size-4" />,
		description: 'Learn the fundamentals of Ika',
		color: 'text-rose-500 dark:text-rose-400',
		bgColor: 'bg-rose-500/10 dark:bg-rose-500/20',
	},
	skills: {
		icon: <Bot className="size-4" />,
		description: 'AI skills for coding agents',
		color: 'text-amber-500 dark:text-amber-400',
		bgColor: 'bg-amber-500/10 dark:bg-amber-500/20',
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
		<Banner id="solana-banner" className="bg-gradient-to-r from-purple-600 via-fuchsia-500 to-pink-500 text-white">
			<a href="https://solana-pre-alpha.ika.xyz" target="_blank" rel="noopener noreferrer" className="flex items-center justify-center gap-3 text-sm font-medium text-white no-underline hover:opacity-90 transition-opacity">
				<Image src="/solana-logo.svg" alt="Solana" width={16} height={16} className="brightness-0 invert" />
				<span>
					Solana Pre-Alpha is live! dWallets now support Solana for native cross-chain signing.
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
