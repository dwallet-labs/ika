'use client';

import { Geist, Geist_Mono } from 'next/font/google';

import './globals.css';
import '@mysten/dapp-kit/dist/index.css';

import ecc from '@bitcoinerlab/secp256k1';
import { getNetworkConfig } from '@ika.xyz/sdk';
import {
	ConnectButton,
	createNetworkConfig,
	SuiClientProvider,
	WalletProvider,
} from '@mysten/dapp-kit';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import * as bitcoin from 'bitcoinjs-lib';

import { IkaClientProvider } from '../components/providers/IkaClientProvider';

// Initialize ECC library for bitcoinjs-lib (required for crypto operations)
// @bitcoinerlab/secp256k1 is pure JavaScript (no WASM) and works well in browsers
// This must be done before any bitcoinjs-lib operations
bitcoin.initEccLib(ecc);

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
	testnet: { url: getFullnodeUrl('testnet') },
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
					<SuiClientProvider
						networks={networkConfig}
						defaultNetwork="testnet"
						createClient={(_, config) =>
							new SuiClient({
								url: config.url,
								mvr: {
									overrides: {
										packages: {
											'@local-pkg/multisig-contract': '0x98eec1dd5a67695bf03d55d355c81eedfcca5f4aee196f295305acdd574b1e94',
										},
									},
								},
							})
						}
					>
						<WalletProvider autoConnect>
							<IkaClientProvider config={getNetworkConfig('testnet')}>
								<div className="min-h-screen bg-zinc-50 text-zinc-900 dark:bg-black dark:text-zinc-100">
									<header className="sticky top-0 z-20 border-b border-zinc-200/60 bg-white/60 backdrop-blur supports-[backdrop-filter]:bg-white/60 dark:border-zinc-800/60 dark:bg-black/40">
										<div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
											<div className="flex items-center gap-2 text-sm font-medium tracking-tight">
												<div className="h-2.5 w-2.5 rounded-full bg-zinc-900 dark:bg-zinc-100" />
												<span>IKA Bitcoin Multisig</span>
											</div>
											<ConnectButton />
										</div>
									</header>
									<main className="mx-auto max-w-5xl px-6 py-8">{children}</main>
								</div>
							</IkaClientProvider>
						</WalletProvider>
					</SuiClientProvider>
				</QueryClientProvider>
			</body>
		</html>
	);
}
