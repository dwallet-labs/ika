import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { Blocks, BookOpen, Code2, FileCode, Server } from 'lucide-react';
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
	sdk: {
		icon: <Code2 className="size-4" />,
		description: 'TypeScript SDK for building with Ika',
		color: 'text-pink-500 dark:text-pink-400',
		bgColor: 'bg-pink-500/10 dark:bg-pink-500/20',
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
	operators: {
		icon: <Server className="size-4" />,
		description: 'Run and operate Ika nodes',
		color: 'text-purple-500 dark:text-purple-400',
		bgColor: 'bg-purple-500/10 dark:bg-purple-500/20',
	},
	'code-examples': {
		icon: <FileCode className="size-4" />,
		description: 'Example code and tutorials',
		color: 'text-violet-500 dark:text-violet-400',
		bgColor: 'bg-violet-500/10 dark:bg-violet-500/20',
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
	);
}
