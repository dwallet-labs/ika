'use client';

import { DAppKitProvider } from '@mysten/dapp-kit-react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import * as React from 'react';

import { dAppKit } from './dapp-kit';

/**
 * dApp Kit 2 replaces the SuiClientProvider/WalletProvider pair with a single
 * provider around a `createDAppKit` instance. React Query stays, because the
 * app uses it for its own data fetching.
 */
export function DappKitProviders({ children }: { children: React.ReactNode }) {
	const [queryClient] = React.useState(() => new QueryClient());

	return (
		<QueryClientProvider client={queryClient}>
			<DAppKitProvider dAppKit={dAppKit}>{children}</DAppKitProvider>
		</QueryClientProvider>
	);
}
