// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
	resolve: {
		alias: {
			// During tests, resolve workspace packages to TS source so we don't
			// need to build before each run.
			'@ika.xyz/sdk/plugin': path.resolve(__dirname, 'src/plugin/index.ts'),
			'@ika.xyz/sdk': path.resolve(__dirname, 'src/index.ts'),
			'@ika.xyz/plugins/sui/source': path.resolve(
				__dirname,
				'../plugins/src/sui/source/index.ts',
			),
			'@ika.xyz/plugins/sui/destination': path.resolve(
				__dirname,
				'../plugins/src/sui/destination/index.ts',
			),
			'@ika.xyz/plugins/sui/publisher': path.resolve(
				__dirname,
				'../plugins/src/sui/publisher/index.ts',
			),
			'@ika.xyz/plugins/solana/destination': path.resolve(
				__dirname,
				'../plugins/src/solana/destination/index.ts',
			),
			'@ika.xyz/plugins/solana/publisher': path.resolve(
				__dirname,
				'../plugins/src/solana/publisher/index.ts',
			),
			'@ika.xyz/plugins/ethereum/destination': path.resolve(
				__dirname,
				'../plugins/src/ethereum/destination/index.ts',
			),
			'@ika.xyz/plugins/ethereum/publisher': path.resolve(
				__dirname,
				'../plugins/src/ethereum/publisher/index.ts',
			),
			'@ika.xyz/plugins/bitcoin/destination': path.resolve(
				__dirname,
				'../plugins/src/bitcoin/destination/index.ts',
			),
			'@ika.xyz/plugins/bitcoin/publisher': path.resolve(
				__dirname,
				'../plugins/src/bitcoin/publisher/index.ts',
			),
			'@ika.xyz/plugins/sui': path.resolve(__dirname, '../plugins/src/sui/index.ts'),
			'@ika.xyz/plugins/solana': path.resolve(__dirname, '../plugins/src/solana/index.ts'),
			'@ika.xyz/plugins/ethereum': path.resolve(__dirname, '../plugins/src/ethereum/index.ts'),
			'@ika.xyz/plugins/bitcoin': path.resolve(__dirname, '../plugins/src/bitcoin/index.ts'),
			'@ika.xyz/plugins': path.resolve(__dirname, '../plugins/src/index.ts'),
		},
	},
	test: {
		minWorkers: 1,
		maxWorkers: 50,
		hookTimeout: 1000000,
		testTimeout: 6_000_000, // 60 minutes
		retry: 0,
		pool: 'forks', // Use forks instead of threads for better memory isolation
		env: {
			NODE_ENV: 'test',
		},
		exclude: ['**/node_modules/**', '**/system-tests/multiple-network-keys/**'],
		coverage: {
			provider: 'v8',
			reporter: ['text', 'html', 'json', 'lcov'],
			reportsDirectory: './coverage',
			exclude: [
				'**/node_modules/**',
				'**/dist/**',
				'**/*.config.*',
				'**/test/**',
				'**/tests/**',
				'**/*.test.*',
				'**/*.spec.*',
				'**/generated/**',
				'**/src/tx/coordinator.ts',
				'**/src/tx/system.ts',
			],
			include: ['src/**/*.ts', 'src/**/*.js'],
			thresholds: {
				global: {
					branches: 50,
					functions: 50,
					lines: 50,
					statements: 50,
				},
			},
		},
	},
});
