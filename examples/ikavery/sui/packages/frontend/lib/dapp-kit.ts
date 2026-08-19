import { getGrpcFullnodeUrl } from '@fesal-packages/ikavery-sui-sdk';
import { createDAppKit } from '@mysten/dapp-kit-core';
import { enokiWalletsInitializer } from '@mysten/enoki';
import { SuiGrpcClient } from '@mysten/sui/grpc';

import { env } from './env';

/**
 * Public Sui fullnodes serve gRPC only, so the whole app — reads, transaction
 * resolution before signing, and execution — runs on `SuiGrpcClient`. That is
 * also why this uses `@mysten/dapp-kit-react`: the legacy `@mysten/dapp-kit`
 * is JSON-RPC only and is no longer updated.
 */
const enokiProviders = (() => {
	if (!env.enokiApiKey) return null;

	// Pin every provider's redirect URI to a single page so only one URL needs
	// to be whitelisted in each OAuth client console.
	const redirectUrl = typeof window === 'undefined' ? undefined : `${window.location.origin}/auth`;

	const providers: Record<string, unknown> = {};
	if (env.googleClientId)
		providers.google = {
			clientId: env.googleClientId,
			redirectUrl,
			// Force Google's account picker every OAuth round-trip. Without this
			// Google silently returns the most-recently-used account, which
			// breaks the multi-Google-account use case (e.g. the importer wants
			// a different identity than the gas payer).
			extraParams: { prompt: 'select_account' },
		};
	if (env.twitchClientId) providers.twitch = { clientId: env.twitchClientId, redirectUrl };
	if (env.facebookClientId) providers.facebook = { clientId: env.facebookClientId, redirectUrl };

	return Object.keys(providers).length > 0 ? providers : null;
})();

export const dAppKit = createDAppKit({
	networks: ['testnet', 'mainnet'] as const,
	defaultNetwork: env.network,
	createClient: (network) =>
		new SuiGrpcClient({
			network,
			baseUrl:
				network === env.network && env.suiRpcUrl ? env.suiRpcUrl : getGrpcFullnodeUrl(network),
		}),
	// zkLogin OAuth flows (Google/Twitch/Facebook) register as Wallet Standard
	// wallets, so they appear in `useWallets()` alongside installed extensions.
	// dApp Kit 2 takes them as an initializer rather than a mount-time effect.
	walletInitializers: enokiProviders
		? [
				enokiWalletsInitializer({
					apiKey: env.enokiApiKey!,
					providers: enokiProviders as never,
				}),
			]
		: undefined,
});

declare module '@mysten/dapp-kit-core' {
	interface Register {
		dAppKit: typeof dAppKit;
	}
}
