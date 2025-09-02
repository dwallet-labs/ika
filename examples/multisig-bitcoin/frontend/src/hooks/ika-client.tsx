import { getNetworkConfig, IkaClient } from '@ika.xyz/sdk';
import { SuiClient } from '@mysten/sui/client';
import { createContext, ReactNode, useContext, useEffect, useState } from 'react';

interface IkaClientContextType {
	ikaClient: IkaClient | null;
	isLoading: boolean;
	error: Error | null;
}

const IkaClientContext = createContext<IkaClientContextType | undefined>(undefined);

interface IkaClientProviderProps {
	children: ReactNode;
	suiClient: SuiClient;
}

export function IkaClientProvider({ children, suiClient }: IkaClientProviderProps) {
	const [ikaClient, setIkaClient] = useState<IkaClient | null>(null);
	const [isLoading, setIsLoading] = useState(true);
	const [error, setError] = useState<Error | null>(null);

	useEffect(() => {
		const initializeClient = async () => {
			try {
				setIsLoading(true);
				setError(null);

				const client = new IkaClient({
					suiClient: suiClient as any,
					config: {
						objects: {
							ikaDWalletCoordinator: {
								initialSharedVersion: 0,
								objectID: '0x1931c676af48b417a2a739bbb1e73d2d92a0fd53b63f7fe31ab4a3a3581c759f',
							},
							ikaSystemObject: {
								initialSharedVersion: 0,
								objectID: '0x8c6ea772acb34f62f9a4297e697271a215836f3c07f206eda6a0684c9f0e5775',
							},
						},
						packages: {
							ikaCommonPackage:
								'0x90a75405949c5b5d886a0b469b8ddf2e3b8952b32ce7453f9dea665193a0881a',
							ikaDwallet2pcMpcPackage:
								'0xf862d3a3ec364e8db2d5d8407c1922220ac8cea2e54175d650fd8bb5e927871e',
							ikaPackage: '0x0f37b6f11f3107855711c6ffb3ac41a4e417124970e156ba2d70cb17796d8486',
							ikaSystemPackage:
								'0xe869ae23ef9fda6484d1eb2b9b10da0579cd91936a3666bd7cc80258bb707c7f',
						},
					},
				});

				await client.initialize();
				setIkaClient(client);
			} catch (err) {
				setError(err as Error);
			} finally {
				setIsLoading(false);
			}
		};

		initializeClient();
	}, [suiClient]);

	const contextValue: IkaClientContextType = {
		ikaClient,
		isLoading,
		error,
	};

	return <IkaClientContext.Provider value={contextValue}>{children}</IkaClientContext.Provider>;
}

export const useIkaClient = () => {
	const context = useContext(IkaClientContext);
	if (context === undefined) {
		throw new Error('useIkaClient must be used within an IkaClientProvider');
	}

	if (context.error) {
		throw context.error;
	}

	return {
		ikaClient: context.ikaClient,
		isLoading: context.isLoading,
	};
};
