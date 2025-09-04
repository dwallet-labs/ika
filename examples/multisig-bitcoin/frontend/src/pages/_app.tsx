import '@/styles/globals.css';
import '@mysten/dapp-kit/dist/index.css';

import {
	createNetworkConfig,
	SuiClientProvider,
	useSuiClient,
	WalletProvider,
} from '@mysten/dapp-kit';
import { getFullnodeUrl } from '@mysten/sui/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { AppProps } from 'next/app';

import { IkaClientProvider } from '@/hooks/ika-client';

// Config options for the networks you want to connect to
const { networkConfig } = createNetworkConfig({
	localnet: { url: getFullnodeUrl('localnet') },
});

const queryClient = new QueryClient();

function AppWithProviders({ Component, pageProps }: AppProps) {
	const suiClient = useSuiClient();

	return (
		<IkaClientProvider suiClient={suiClient}>
			<Component {...pageProps} />
		</IkaClientProvider>
	);
}

export default function App(props: AppProps) {
	return (
		<QueryClientProvider client={queryClient}>
			<SuiClientProvider networks={networkConfig} defaultNetwork="localnet">
				<WalletProvider autoConnect>
					<AppWithProviders {...props} />
				</WalletProvider>
			</SuiClientProvider>
		</QueryClientProvider>
	);
}
