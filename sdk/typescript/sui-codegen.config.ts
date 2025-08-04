import type { SuiCodegenConfig } from '@mysten/codegen';

const config: SuiCodegenConfig = {
	output: './generated',
	packages: [
		{
			package: '@local-pkg/2pc-mpc',
			path: '../../contracts/ika_dwallet_2pc_mpc',
		},
		{
			package: '@local-pkg/common',
			path: '../../contracts/ika_common',
		},
		{
			package: '@local-pkg/system',
			path: '../../contracts/ika_system',
		},
		{
			package: '@local-pkg/ika',
			path: '../../contracts/ika',
		},
	],
};

export default config;
