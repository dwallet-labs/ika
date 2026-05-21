import { Banner } from 'fumadocs-ui/components/banner';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { ArrowRight } from 'lucide-react';
import Image from 'next/image';
import type { ReactNode } from 'react';

import { source } from '@/lib/source';

import { baseOptions } from '../layout.config';

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
			<DocsLayout tree={source.pageTree} {...baseOptions}>
				{children}
			</DocsLayout>
		</>
	);
}
