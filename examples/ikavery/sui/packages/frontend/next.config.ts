import type { NextConfig } from 'next';

const config: NextConfig = {
	reactStrictMode: true,
	transpilePackages: [
		'@ika.xyz/sdk',
		'@fesal-packages/ikavery-core',
		'@fesal-packages/ikavery-frontend-ui',
		'@fesal-packages/ikavery-sui-sdk',
	],
	experimental: {
		optimizePackageImports: ['@solana/web3.js', '@solana/spl-token'],
	},
	// Slush / Enoki / OAuth wallets sign through a popup and poll
	// `popup.closed` to detect completion. Next.js's default COOP of
	// `same-origin` blocks that cross-origin read, leaving the wallet
	// promise hanging forever. `same-origin-allow-popups` keeps the page
	// itself isolated but lets popups it opens communicate back.
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
	// Turbopack is the Next 16 default. The workspace packages are consumed as
	// built JS, so the webpack `extensionAlias` below is only needed by the
	// `--webpack` path; declaring an empty turbopack config opts this app into
	// the default builder explicitly.
	turbopack: {},
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
