'use client';

import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { BookOpen, Bot, Code2, Globe, Library, Terminal } from 'lucide-react';
import type { PageTree } from 'fumadocs-core/server';
import type { ReactNode } from 'react';

type TabConfig = {
	icon: ReactNode;
	description: string;
	color: string;
	bgColor: string;
};

const tabConfig: Record<string, TabConfig> = {
	learn: {
		icon: <BookOpen className="size-4" />,
		description: 'Concepts, trust model, and cryptography',
		color: 'text-rose-500 dark:text-rose-400',
		bgColor: 'bg-rose-500/10 dark:bg-rose-500/20',
	},
	build: {
		icon: <Code2 className="size-4" />,
		description: 'SDK, plugins, Move integration, recipes',
		color: 'text-pink-500 dark:text-pink-400',
		bgColor: 'bg-pink-500/10 dark:bg-pink-500/20',
	},
	'solana-integration': {
		icon: <Globe className="size-4" />,
		description: 'Solana coordination chain (pre-alpha)',
		color: 'text-purple-500 dark:text-purple-400',
		bgColor: 'bg-purple-500/10 dark:bg-purple-500/20',
	},
	operate: {
		icon: <Terminal className="size-4" />,
		description: 'CLI, validators, and network configs',
		color: 'text-emerald-500 dark:text-emerald-400',
		bgColor: 'bg-emerald-500/10 dark:bg-emerald-500/20',
	},
	reference: {
		icon: <Library className="size-4" />,
		description: 'Curves, events, configs, Move modules',
		color: 'text-fuchsia-500 dark:text-fuchsia-400',
		bgColor: 'bg-fuchsia-500/10 dark:bg-fuchsia-500/20',
	},
	'ai-skills': {
		icon: <Bot className="size-4" />,
		description: 'AI skills for coding agents',
		color: 'text-amber-500 dark:text-amber-400',
		bgColor: 'bg-amber-500/10 dark:bg-amber-500/20',
	},
};

function TabIcon({ config }: { config: TabConfig }) {
	return (
		<div
			className={`relative flex items-center justify-center size-8 rounded-lg ${config.bgColor} ${config.color} transition-all duration-200`}
		>
			{config.icon}
		</div>
	);
}

function SidebarSectionLabel({ item }: { item: PageTree.Separator }) {
	return (
		<div className="mt-6 mb-1 flex items-center gap-3 px-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-fd-muted-foreground/80 select-none">
			<span>{item.name}</span>
			<span className="flex-1 h-px bg-fd-border" />
		</div>
	);
}

export default function DocsLayoutClient({
	tree,
	children,
	...base
}: BaseLayoutProps & { tree: PageTree.Root; children: ReactNode }) {
	return (
		<DocsLayout
			tree={tree}
			{...base}
			sidebar={{
				components: {
					Separator: SidebarSectionLabel,
				},
				tabs: {
					transform(option) {
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
	);
}
