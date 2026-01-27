import './global.css';

import { RootProvider } from 'fumadocs-ui/provider';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';

export const metadata: Metadata = {
	title: {
		template: '%s | Ika Docs',
		default: 'Ika Docs',
	},
	description: 'Ika Documentation - Multi-chain interoperability with dWallets',
	metadataBase: new URL('https://docs.ika.xyz'),
	icons: {
		icon: '/ika-logo.png',
	},
};

export default function RootLayout({ children }: { children: ReactNode }) {
	return (
		<html lang="en" suppressHydrationWarning>
			<body>
				<RootProvider>{children}</RootProvider>
			</body>
		</html>
	);
}
