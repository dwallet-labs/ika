// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { defineConfig } from 'vitest/config';

export default defineConfig({
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
		// `test/live` talks to the public mainnet/testnet fullnodes, so it is not
		// part of any localnet-backed run — invoke it with `pnpm test:live`.
		exclude: ['**/node_modules/**', '**/system-tests/multiple-network-keys/**', '**/test/live/**'],
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
