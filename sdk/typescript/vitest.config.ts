// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: BSD-3-Clause-Clear

import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		minWorkers: 1,
		maxWorkers: 1,
		hookTimeout: 1000000,
		testTimeout: 1000000, // 10 minutes
		retry: 0,
		env: {
			NODE_ENV: 'test',
		},
	},
});
