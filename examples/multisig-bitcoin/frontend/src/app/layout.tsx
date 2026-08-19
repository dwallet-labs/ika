'use client';

import { Geist, Geist_Mono } from 'next/font/google';

import './globals.css';

import ecc from '@bitcoinerlab/secp256k1';
import { getNetworkConfig } from '@ika.xyz/sdk';
import { DAppKitProvider } from '@mysten/dapp-kit-react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import * as bitcoin from 'bitcoinjs-lib';
import { Toaster } from 'sonner';

import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { IkaClientProvider } from '../components/providers/IkaClientProvider';
import { MultisigProvider } from '../contexts/MultisigContext';
import { dAppKit } from '../lib/sui';

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

const queryClient = new QueryClient({
	defaultOptions: {
		queries: {
			// Enable refetching on window focus for better UX
			refetchOnWindowFocus: true,
			// Enable refetch on reconnect
			refetchOnReconnect: true,
			// Data is fresh for 30 seconds, then will refetch on next use
			staleTime: 30 * 1000,
			// Keep in cache for 5 minutes
			gcTime: 5 * 60 * 1000,
			// Retry failed requests only once
			retry: 1,
		},
	},
});

export default function RootLayout({
	children,
}: Readonly<{
	children: React.ReactNode;
}>) {
	return (
		<html lang="en" className="dark">
			<head>
				<title>bitisi - bitcoin multisig on sui</title>
				<meta
					name="description"
					content="Secure bitcoin multisig wallets powered by IKA protocol on Sui"
				/>
			</head>
			<body className={`${geistMono.variable} antialiased`}>
				<ErrorBoundary>
					<QueryClientProvider client={queryClient}>
						<DAppKitProvider dAppKit={dAppKit}>
							<IkaClientProvider config={getNetworkConfig('testnet')}>
								<MultisigProvider>
									{children}
									<Toaster position="top-right" richColors />
								</MultisigProvider>
							</IkaClientProvider>
						</DAppKitProvider>
					</QueryClientProvider>
				</ErrorBoundary>
			</body>
		</html>
	);
}
