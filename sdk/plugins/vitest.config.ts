// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sdkRoot = path.resolve(__dirname, '../typescript');

export default defineConfig({
	resolve: {
		alias: {
			// Resolve workspace packages to TS source so tests don't need a build.
			'@ika.xyz/sdk/plugin': path.resolve(sdkRoot, 'src/plugin/index.ts'),
			'@ika.xyz/sdk': path.resolve(sdkRoot, 'src/index.ts'),
			'@ika.xyz/plugins/sui/source': path.resolve(__dirname, 'src/sui/source/index.ts'),
			'@ika.xyz/plugins/sui/destination': path.resolve(__dirname, 'src/sui/destination/index.ts'),
			'@ika.xyz/plugins/sui/publisher': path.resolve(__dirname, 'src/sui/publisher/index.ts'),
			'@ika.xyz/plugins/solana/destination': path.resolve(
				__dirname,
				'src/solana/destination/index.ts',
			),
			'@ika.xyz/plugins/solana/publisher': path.resolve(__dirname, 'src/solana/publisher/index.ts'),
			'@ika.xyz/plugins/ethereum/destination': path.resolve(
				__dirname,
				'src/ethereum/destination/index.ts',
			),
			'@ika.xyz/plugins/ethereum/publisher': path.resolve(
				__dirname,
				'src/ethereum/publisher/index.ts',
			),
			'@ika.xyz/plugins/bitcoin/destination': path.resolve(
				__dirname,
				'src/bitcoin/destination/index.ts',
			),
			'@ika.xyz/plugins/bitcoin/publisher': path.resolve(
				__dirname,
				'src/bitcoin/publisher/index.ts',
			),
			'@ika.xyz/plugins/sui': path.resolve(__dirname, 'src/sui/index.ts'),
			'@ika.xyz/plugins/solana': path.resolve(__dirname, 'src/solana/index.ts'),
			'@ika.xyz/plugins/ethereum': path.resolve(__dirname, 'src/ethereum/index.ts'),
			'@ika.xyz/plugins/bitcoin': path.resolve(__dirname, 'src/bitcoin/index.ts'),
			'@ika.xyz/plugins': path.resolve(__dirname, 'src/index.ts'),
		},
	},
	test: {
		minWorkers: 1,
		maxWorkers: 50,
		hookTimeout: 1000000,
		testTimeout: 6_000_000, // 60 minutes for localnet/testnet flows
		retry: 0,
		pool: 'forks',
		env: {
			NODE_ENV: 'test',
		},
		exclude: ['**/node_modules/**', '**/dist/**'],
		coverage: {
			provider: 'v8',
			reporter: ['text', 'html', 'json', 'lcov'],
			reportsDirectory: './coverage',
			exclude: [
				'**/node_modules/**',
				'**/dist/**',
				'**/*.config.*',
				'**/test/**',
				'**/*.test.*',
				'**/*.spec.*',
				'examples/**',
			],
			include: ['src/**/*.ts'],
		},
	},
});
