import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		minWorkers: 1,
		maxWorkers: 4,
		hookTimeout: 1000000,
		testTimeout: 600_000,
		retry: 0,
		pool: 'forks',
		env: {
			NODE_ENV: 'test',
		},
	},
});
