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
								objectID: '0x78324f81d37437e3aa4e5486a8d666121ffb0644f7ae1db4f295a1a542a87905',
							},
							ikaSystemObject: {
								initialSharedVersion: 0,
								objectID: '0xcfecb9bd8b5b8753ded313b93e7c8aa14e9f1eb752c6914fa0e717b6859a113a',
							},
						},
						packages: {
							ikaCommonPackage:
								'0xfbdfdb133c9de288aa3c68261d46dc0a6ba9e72fff7ffd67c6febf6c0f5627b3',
							ikaDwallet2pcMpcPackage:
								'0x0474150a1cdfde54a73b220c63b25deeb06bbbfe34f99ae8ae6dbeead2d4d09e',
							ikaPackage: '0x877ac493d6cea5721490cb0cf7f994ebba5c7035ce9263deb7a6e9ed81cf72a1',
							ikaSystemPackage:
								'0x16416a19f097fce5bdb4b11af0bd7a7f36236b4fdf3e31785231e3ed83d9cd3f',
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
