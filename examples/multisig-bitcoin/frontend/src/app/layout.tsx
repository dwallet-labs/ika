'use client';

import { Geist, Geist_Mono } from 'next/font/google';

import './globals.css';
import '@mysten/dapp-kit/dist/index.css';

import ecc from '@bitcoinerlab/secp256k1';
import {
	ConnectButton,
	createNetworkConfig,
	SuiClientProvider,
	WalletProvider,
} from '@mysten/dapp-kit';
import { getFullnodeUrl } from '@mysten/sui/client';
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
							<IkaClientProvider
								config={{
									objects: {
										ikaDWalletCoordinator: {
											initialSharedVersion: 0,
											objectID:
												'0xfd17d69fe2e7fac5203e9f4e4174b8f9045bd5ac7c41c9e99bcf6e86c443d91c',
										},
										ikaSystemObject: {
											initialSharedVersion: 0,
											objectID:
												'0xaa955bf170517b719af82c1ecc09ab8dcb940bcc34e033d395be99c0d20002ad',
										},
									},
									packages: {
										ikaDwallet2pcMpcPackage:
											'0x4bd485cc90febffe238834cba1c62cce297cd4c5594bdbc596860f4c712aa0e4',
										ikaSystemPackage:
											'0xe2fd2df7bc9f769688445e90c3c042e61c0c6a44b35e419e214eaedc75353f82',
										ikaPackage:
											'0xee5d4da55ded42f64bad7b9e33297d9fb9646875802caaf654c291dfb964f235',
										ikaCommonPackage:
											'0xc7235df3ff0f78075b108b276941b6e0c4bdd9d3282d4199a73b24b6e61fbb00',
									},
								}}
							>
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
