import { createDAppKit } from '@mysten/dapp-kit-core';
import { SuiGrpcClient } from '@mysten/sui/grpc';

/**
 * Public Sui fullnodes no longer serve JSON-RPC, so every read this app makes —
 * and every transaction dApp Kit resolves before a wallet signs it — goes over
 * gRPC. That is also why this uses `@mysten/dapp-kit-react` rather than the
 * legacy `@mysten/dapp-kit`: the old package is JSON-RPC only.
 */
export const SUI_GRPC_URLS = {
	localnet: 'http://127.0.0.1:9000',
	testnet: 'https://fullnode.testnet.sui.io:443',
	mainnet: 'https://fullnode.mainnet.sui.io:443',
} as const;

export type SuiNetwork = keyof typeof SUI_GRPC_URLS;

const MVR_OVERRIDES = {
	overrides: {
		packages: {
			'@local-pkg/multisig-contract':
				'0x98eec1dd5a67695bf03d55d355c81eedfcca5f4aee196f295305acdd574b1e94',
		},
	},
};

export function createSuiClient(network: SuiNetwork): SuiGrpcClient {
	return new SuiGrpcClient({
		network,
		baseUrl: SUI_GRPC_URLS[network],
		mvr: MVR_OVERRIDES,
	});
}

export const dAppKit = createDAppKit({
	networks: ['testnet', 'mainnet', 'localnet'] as const,
	defaultNetwork: 'testnet',
	createClient: (network) => createSuiClient(network),
});

declare module '@mysten/dapp-kit-core' {
	interface Register {
		dAppKit: typeof dAppKit;
	}
}
