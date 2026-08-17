import type { SuiCodegenConfig } from '@mysten/codegen';

const config: SuiCodegenConfig = {
	output: './src/generated',
	packages: [
		{
			package: '@local-pkg/recovery',
			path: '../contracts/recovery',
			packageName: 'recovery',
		},
	],
	generateSummaries: false,
};

export default config;
