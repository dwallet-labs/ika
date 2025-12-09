import path from 'path';
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
	// Use webpack instead of Turbopack for now to support .js import resolution
	webpack: (config, { isServer }) => {
		// Resolve .js imports to .ts/.tsx files
		config.resolve.extensionAlias = {
			'.js': ['.ts', '.tsx', '.js', '.jsx'],
			'.jsx': ['.tsx', '.jsx'],
		};

		// Enable WebAssembly support for ika-wasm (SDK's WASM module)
		// Note: @bitcoinerlab/secp256k1 is pure JS, no WASM needed
		config.experiments = {
			...config.experiments,
			asyncWebAssembly: true,
		};

		// Handle .wasm files - use asset/resource for wasm-pack modules
		// This allows them to be loaded via fetch/URL
		config.module.rules.push({
			test: /\.wasm$/,
			type: 'asset/resource',
		});

		// Ignore 'wbg' module resolution - it's a virtual module created internally by wasm-pack
		// Point it to an empty module
		if (!isServer) {
			config.resolve.alias = {
				...config.resolve.alias,
				wbg: path.resolve(__dirname, 'src/utils/empty-wbg.js'),
			};
		}

		return config;
	},
	// Add empty turbopack config to silence the warning
	// We'll use webpack for now until Turbopack supports extensionAlias
	turbopack: {},
};

export default nextConfig;
