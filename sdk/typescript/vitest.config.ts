// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		minWorkers: 1,
		maxWorkers: 30,
		hookTimeout: 1000000,
		testTimeout: 6_000_000, // 60 minutes
		retry: 0,
		env: {
			NODE_ENV: 'test',
		},
	},
});
