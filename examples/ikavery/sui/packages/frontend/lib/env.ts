/**
 * Frontend environment knobs. NEXT_PUBLIC_* so they ship to the browser.
 *
 * These have demo defaults that match the v3 caller-pays deployment on Sui
 * testnet so the page works out of the box. For self-hosting, override them
 * via env.
 */
export const env = {
	network: (process.env.NEXT_PUBLIC_SUI_NETWORK ?? 'testnet') as 'testnet' | 'mainnet',
	// Default to PublicNode — the official Sui RPCs aggressively rate-limit and
	// tank the demo. Override with NEXT_PUBLIC_SUI_RPC_URL for self-hosting.
	suiRpcUrl:
		process.env.NEXT_PUBLIC_SUI_RPC_URL ??
		(process.env.NEXT_PUBLIC_SUI_NETWORK === 'mainnet'
			? 'https://sui-rpc.publicnode.com'
			: 'https://sui-testnet-rpc.publicnode.com'),
	recoveryPackageId:
		process.env.NEXT_PUBLIC_RECOVERY_PACKAGE_ID ??
		'0x666f666d565e710308fe0cf7eaa6679bdd1abe219c39f3a12020f1c16a977678',
	recoveryRegistryId:
		process.env.NEXT_PUBLIC_RECOVERY_REGISTRY_ID ??
		'0x283060a2545af73e93b64010adc9a72d9b93617a2e417dfa34e06c2ae7b9a941',
	rpId:
		process.env.NEXT_PUBLIC_RP_ID ??
		(typeof window !== 'undefined' ? window.location.hostname : 'localhost'),
	rpName: process.env.NEXT_PUBLIC_RP_NAME ?? 'Recovery',
	solanaRpc: process.env.NEXT_PUBLIC_SOLANA_RPC ?? 'https://api.devnet.solana.com',
	faucetUrl: process.env.NEXT_PUBLIC_SUI_FAUCET ?? 'https://faucet.testnet.sui.io/v2/gas',
	enokiApiKey: process.env.NEXT_PUBLIC_ENOKI_API_KEY,
	googleClientId: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID,
	twitchClientId: process.env.NEXT_PUBLIC_TWITCH_CLIENT_ID,
	facebookClientId: process.env.NEXT_PUBLIC_FACEBOOK_CLIENT_ID,
};
