'use client';

import { DynamicContextProvider } from '@dynamic-labs/sdk-react-core';
import { SolanaWalletConnectors } from '@dynamic-labs/solana';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import * as React from 'react';

import { DYNAMIC_ENVIRONMENT_ID } from '@/lib/env';

/**
 * App-root providers: Dynamic for wallet auth + TanStack Query for the
 * vault dashboard's polling reads. The Sui app at `sui.ikavery.com` runs
 * a separate dapp-kit + Sui-flavoured provider tree.
 */
export function DynamicProviders({ children }: { children: React.ReactNode }) {
	const [queryClient] = React.useState(() => new QueryClient());
	return (
		<QueryClientProvider client={queryClient}>
			<DynamicContextProvider
				settings={{
					environmentId: DYNAMIC_ENVIRONMENT_ID,
					walletConnectors: [SolanaWalletConnectors],
					// Devnet-only demo — surface the network choice up-front in the
					// widget so a returning user with a mainnet wallet sees the
					// mismatch immediately rather than at sweep time.
					networkValidationMode: 'always',
				}}
			>
				{children}
			</DynamicContextProvider>
		</QueryClientProvider>
	);
}
