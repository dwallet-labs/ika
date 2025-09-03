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
								objectID: '0xf846b4ab160ee09c0e7c651e01cdf06a2775a476735292b49165f1ce0bc1b909',
							},
							ikaSystemObject: {
								initialSharedVersion: 0,
								objectID: '0x9b0208aa6bdf3105a94d7062b577fddf6fd0e28913f821547beeca6ddae4dd7a',
							},
						},
						packages: {
							ikaCommonPackage:
								'0x43730a07bd232acf53845950a8da594dc9c1a00ee4fd2e284d0a580ba4a1a9cb',
							ikaDwallet2pcMpcPackage:
								'0x017d21a12af8a07f04fcb70609561c73bf8dccc97b4e228f15c304d23dc7c704',
							ikaPackage: '0x1519776790584d156e128d4f4251501094a6e28aa784b7d71a06a39c344889bf',
							ikaSystemPackage:
								'0xccc67ba9f28cc5f09b103f87ddf230516d9dd60f96e48ea01b0eae44f9646ee2',
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
