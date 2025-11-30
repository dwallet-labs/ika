'use client';

import { getNetworkConfig, IkaClient, type IkaConfig, type Network } from '@ika.xyz/sdk';
import { useSuiClient } from '@mysten/dapp-kit';
import { createContext, useContext, useMemo, type ReactNode } from 'react';

export interface IkaClientContextType {
	ikaClient: IkaClient;
}

export const IkaClientContext = createContext<IkaClientContextType | undefined>(undefined);

export interface IkaClientProviderProps {
	children: ReactNode;
	network?: Network;
	config?: IkaConfig;
}

export function IkaClientProvider({
	children,
	network = 'testnet',
	config,
}: IkaClientProviderProps) {
	const suiClient = useSuiClient();

	const ikaClient = useMemo(() => {
		const ikaConfig = config || getNetworkConfig(network);

		return new IkaClient({
			suiClient,
			config: ikaConfig,
			cache: true,
		});
	}, [suiClient, network, config]);

	const value = useMemo(
		() => ({
			ikaClient,
		}),
		[ikaClient],
	);

	return <IkaClientContext.Provider value={value}>{children}</IkaClientContext.Provider>;
}
