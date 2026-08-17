'use client';

import { Shell } from '@fesal-packages/ikavery-frontend-ui';
import { AnimatePresence, motion } from 'framer-motion';
import { usePathname } from 'next/navigation';
import type * as React from 'react';

import { AppDisclaimerModal } from '@/components/app-disclaimer-modal';
import { AppShellHeader } from '@/components/app-shell-header';

export default function VaultLayout({ children }: { children: React.ReactNode }) {
	const pathname = usePathname();
	return (
		<Shell>
			<AppDisclaimerModal />
			<AppShellHeader />
			<main className="mx-auto max-w-[1280px] px-4 sm:px-6 lg:px-10 py-10 sm:py-14 lg:py-20">
				<AnimatePresence mode="wait">
					<motion.div
						key={pathname}
						initial={{ opacity: 0, y: 16, filter: 'blur(8px)' }}
						animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
						exit={{ opacity: 0, y: -8, filter: 'blur(8px)' }}
						transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
					>
						{children}
					</motion.div>
				</AnimatePresence>
			</main>
		</Shell>
	);
}
