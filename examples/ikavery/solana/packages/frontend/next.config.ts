import type { NextConfig } from 'next';

const config: NextConfig = {
	reactStrictMode: true,
	transpilePackages: [
		'@fesal-packages/ikavery-core',
		'@fesal-packages/ikavery-frontend-ui',
		'@fesal-packages/ikavery-solana-sdk',
		// Ships raw `.ts` source — needs the swc loader chain. The wrapper
		// depends on `@grpc/grpc-js` which is Node-only, so this only ever
		// gets pulled into server-side bundles (the api/seal-prepare route).
		'@ika.xyz/pre-alpha-solana-client',
	],
	experimental: {
		optimizePackageImports: ['@solana/web3.js', '@solana/spl-token'],
	},
	// Dynamic's embedded-wallet flow signs through a popup and polls
	// `popup.closed` to detect completion. Default Next.js COOP of
	// `same-origin` blocks the cross-origin read, so the wallet promise
	// hangs forever. `same-origin-allow-popups` keeps the page isolated
	// but lets popups it opens communicate back.
	async headers() {
		return [
			{
				source: '/:path*',
				headers: [
					{
						key: 'Cross-Origin-Opener-Policy',
						value: 'same-origin-allow-popups',
					},
				],
			},
		];
	},
	webpack: (cfg) => {
		cfg.resolve = cfg.resolve ?? {};
		cfg.resolve.extensionAlias = {
			...(cfg.resolve.extensionAlias ?? {}),
			'.js': ['.ts', '.tsx', '.js'],
			'.mjs': ['.mts', '.mjs'],
		};
		return cfg;
	},
};

export default config;
