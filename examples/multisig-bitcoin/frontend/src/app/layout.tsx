'use client';

import { Geist, Geist_Mono } from 'next/font/google';

import './globals.css';

import { createNetworkConfig, SuiClientProvider, WalletProvider } from '@mysten/dapp-kit';
import { getFullnodeUrl } from '@mysten/sui/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { IkaClientProvider } from '../components/providers/IkaClientProvider';

const geistSans = Geist({
	variable: '--font-geist-sans',
	subsets: ['latin'],
});

const geistMono = Geist_Mono({
	variable: '--font-geist-mono',
	subsets: ['latin'],
});

const queryClient = new QueryClient();

const { networkConfig } = createNetworkConfig({
	localnet: { url: getFullnodeUrl('localnet') },
	mainnet: { url: getFullnodeUrl('mainnet') },
});

export default function RootLayout({
	children,
}: Readonly<{
	children: React.ReactNode;
}>) {
	return (
		<html lang="en">
			<body className={`${geistSans.variable} ${geistMono.variable} antialiased`}>
				<QueryClientProvider client={queryClient}>
					<SuiClientProvider networks={networkConfig} defaultNetwork="localnet">
						<WalletProvider autoConnect>
							<IkaClientProvider>{children}</IkaClientProvider>
						</WalletProvider>
					</SuiClientProvider>
				</QueryClientProvider>
			</body>
		</html>
	);
}
