import type { SuiClientTypes } from '@mysten/sui/client';

/**
 * Public Sui fullnodes no longer serve JSON-RPC, and `@mysten/sui` ships no
 * gRPC equivalent of `getJsonRpcFullnodeUrl`, so the endpoints live here.
 */
const GRPC_URLS: Record<string, string> = {
	localnet: 'http://127.0.0.1:9000',
	devnet: 'https://fullnode.devnet.sui.io:443',
	testnet: 'https://fullnode.testnet.sui.io:443',
	mainnet: 'https://fullnode.mainnet.sui.io:443',
};

export function getGrpcFullnodeUrl(network: SuiClientTypes.Network): string {
	const url = GRPC_URLS[network];
	if (!url) throw new Error(`No gRPC endpoint known for network "${network}"`);
	return url;
}
